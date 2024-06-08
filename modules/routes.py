# modules/routes.py
import sys,ast, uuid, json, random, requests, html, os, re, shutil, traceback, time, schedule, os, platform, tempfile, socket
from threading import Thread
from config import Config
from flask import Flask, render_template, flash, redirect, url_for, request, Blueprint, jsonify, session, abort, current_app, send_from_directory
from flask import copy_current_request_context, g
from flask_login import current_user, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from flask_mail import Message as MailMessage
from wtforms.validators import DataRequired, Email, Length
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.orm import joinedload
from sqlalchemy import func, Integer, Text, case
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename

from werkzeug.security import generate_password_hash, check_password_hash




from modules import db, mail, cache
from functools import wraps
from uuid import uuid4
from datetime import datetime, timedelta
from PIL import Image as PILImage
from PIL import ImageOps
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from authlib.jose import jwt

from urllib.parse import unquote



from modules.forms import (
    UserPasswordForm, UserDetailForm, EditProfileForm, NewsletterForm, WhitelistForm, EditUserForm, 
    UserManagementForm, CsrfProtectForm, LoginForm, ResetPasswordRequestForm, RegistrationForm, 
    CreateUserForm, UserPreferencesForm, InviteForm, CsrfForm, LabForm, FlagSubmissionForm
)

from modules.models import (
    User, Whitelist, UserPreference, GlobalSettings, InviteToken, Lab, Challenge, Host, Flag, UserProgress
)
from modules.utilities import (
    admin_required, _authenticate_and_redirect, square_image, send_email, send_password_reset_email
)


bp = Blueprint('main', __name__)
s = URLSafeTimedSerializer('YMecr3tK?IzzsSa@e!Zithpze') 
has_initialized_whitelist = False
has_upgraded_admin = False
has_initialized_setup = False
app_start_time = datetime.now()
app_version = '1.2.1'

@bp.before_app_request
def initial_setup():
    global has_initialized_setup
    if has_initialized_setup:
        return
    has_initialized_setup = True
    app_start_time = datetime.now()  # Record the startup time

    # Initialize whitelist
    try:
        if not Whitelist.query.first():
            default_email = Config.INITIAL_WHITELIST
            default_whitelist = Whitelist(email=default_email)
            db.session.add(default_whitelist)
            db.session.commit()
            print("Default email added to Whitelist.")
    except IntegrityError:
        db.session.rollback()
        print('Default email already exists in Whitelist.')
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f'error adding default email to Whitelist: {e}')

    # Upgrade first user to admin
    try:
        user = User.query.get(1)
        if user and user.role != 'admin':
            user.role = 'admin'
            user.is_email_verified = True
            db.session.commit()
            print(f"User '{user.name}' (ID: 1) upgraded to admin.")
        elif not user:
            print("No user with ID 1 found in the database.")
        else:
            print("User with ID 1 already has admin role.")
    except IntegrityError:
        db.session.rollback()
        print('error while trying to upgrade user to admin.')
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f'error upgrading user to admin: {e}')

@bp.context_processor
@cache.cached(timeout=500, key_prefix='global_settings')
def inject_settings():
    settings_record = GlobalSettings.query.first()
    if settings_record:
        # Fetch existing settings
        show_logo = settings_record.settings.get('showSystemLogo', False)
        show_help_button = settings_record.settings.get('showHelpButton', False)
        enable_web_links = settings_record.settings.get('enableWebLinksOnDetailsPage', False)
        enable_server_status = settings_record.settings.get('enableServerStatusFeature', False)
        enable_newsletter = settings_record.settings.get('enableNewsletterFeature', False)  # Added setting
    else:
        # Default values if no settings_record is found
        show_logo = True
        show_help_button = True
        enable_web_links = True
        enable_server_status = True
        enable_newsletter = True  # Consider what your default should be

    return dict(
        show_logo=show_logo, 
        show_help_button=show_help_button, 
        enable_web_links=enable_web_links,
        enable_server_status=enable_server_status,
        enable_newsletter=enable_newsletter  # Make sure to return it
    )

@bp.context_processor
def utility_processor():
    return dict(datetime=datetime)




@bp.route('/restricted')
@login_required
def restricted():
    print("Route: /restricted")
    return render_template('site/restricted_area.html', title='Restricted Area')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.restricted'))

    print("Route: /login")
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(name=username).first()

        if user:
            if not user.is_email_verified:
                flash('Your account is not activated, check your email.', 'warning')
                return redirect(url_for('main.login'))

            if not user.state:
                flash('Your account has been banned.', 'error')
                print(f"Error: Attempted login to disabled account - User: {username}")
                return redirect(url_for('main.login'))

            return _authenticate_and_redirect(username, password)
        else:
            flash('Invalid username or password. USERNAMES ARE CASE SENSITIVE!', 'error')
            return redirect(url_for('main.login'))

    return render_template('login/login.html', form=form)


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.login'))
    print("Route: /register")

    # Attempt to get the invite token from the query parameters
    invite_token_from_url = request.args.get('token')
    print(f"Invite token from URL: {invite_token_from_url}")
    invite = None
    if invite_token_from_url:
        invite = InviteToken.query.filter_by(token=invite_token_from_url, used=False).first()
        print(f"Invite found: {invite}")
        if invite and invite.expires_at >= datetime.utcnow():
            # The invite is valid; skip the whitelist check later
            pass
        else:
            invite = None  # Invalidate
            flash('The invite is invalid or has expired.', 'warning')
            return redirect(url_for('main.register'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            email_address = form.email.data.lower()
            existing_user_email = User.query.filter(func.lower(User.email) == email_address).first()
            if existing_user_email:
                print(f"/register: Email already in use - {email_address}")
                flash('This email is already in use. Please use a different email or log in.')
                return redirect(url_for('main.register'))
                    # Proceed with the whitelist check only if no valid invite token is provided
            if not invite:
                whitelist = Whitelist.query.filter(func.lower(Whitelist.email) == email_address).first()
                if not whitelist:
                    flash('Your email is not whitelisted.')
                    return redirect(url_for('main.register'))

            existing_user = User.query.filter_by(name=form.username.data).first()
            if existing_user is not None:
                print(f"/register: User already exists - {form.username.data}")
                flash('User already exists. Please Log in.')
                return redirect(url_for('main.register'))

            user_uuid = str(uuid4())
            existing_uuid = User.query.filter_by(user_id=user_uuid).first()
            if existing_uuid is not None:
                print("/register: UUID collision detected.")
                flash('An error occurred while registering. Please try again.')
                return redirect(url_for('main.register'))

            user = User(
                user_id=user_uuid,
                name=form.username.data,
                email=form.email.data.lower(),  # Ensuring lowercase
                role='user',
                is_email_verified=False,
                email_verification_token=s.dumps(form.email.data, salt='email-confirm'),
                token_creation_time=datetime.utcnow(),
                created=datetime.utcnow(),
                # invited_by=invite.creator_user_id if invite else None
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            print(f"Invite Token from URL: {invite_token_from_url}")

            if invite:
                print(f"Found valid invite: {invite.token}, expires at: {invite.expires_at}, used: {invite.used}")
                invite.used = True
                db.session.commit()
            else:
                print("No valid invite found or invite expired/used.")
            # Verification email
            verification_token = user.email_verification_token
            confirm_url = url_for('main.confirm_email', token=verification_token, _external=True)
            html = render_template('login/registration_activate.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(user.email, subject, html)


            flash('A confirmation email has been sent via email.', 'success')
            return redirect(url_for('site.index'))
        except IntegrityError as e:
            db.session.rollback()
            print(f"IntegrityError occurred: {e}")
            flash('error while registering. Please try again.')

    return render_template('login/registration.html', title='Register', form=form)


@bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=900)  # 15 minutes
    except SignatureExpired:
        return render_template('login/confirmation_expired.html'), 400
    except BadSignature:
        return render_template('login/confirmation_invalid.html'), 400

    user = User.query.filter_by(email=email).first_or_404()
    if user.is_email_verified:
        return render_template('login/registration_already_confirmed.html')
    else:
        user.is_email_verified = True
        db.session.add(user)
        db.session.commit()
        return render_template('login/confirmation_success.html')


@bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.login'))
    form = ResetPasswordRequestForm()
    
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            if user.token_creation_time and (datetime.utcnow() - user.token_creation_time).total_seconds() < 120:
                flash('Please wait a bit before requesting another password reset.')
                return redirect(url_for('main.login'))
            password_reset_token = str(uuid.uuid4())
            user.password_reset_token = password_reset_token
            user.token_creation_time = datetime.utcnow()
            db.session.commit()
            send_password_reset_email(user.email, password_reset_token)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('main.login'))

    return render_template('login/reset_password_request.html', form=form)

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.login'))

    user = User.query.filter_by(password_reset_token=token).first()
    if not user or user.token_creation_time + timedelta(minutes=15) < datetime.utcnow():
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('main.login'))

    form = CsrfProtectForm()

    if form.validate_on_submit():
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html', form=form, token=token)
        user.set_password(new_password)
        user.password_reset_token = None
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('main.login'))

    return render_template('login/reset_password.html', form=form, token=token)


@bp.route('/login/invites', methods=['GET', 'POST'])
@login_required
def invites():
    form = InviteForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        # Ensure the user has invites left to send
        current_invites = InviteToken.query.filter_by(creator_user_id=current_user.user_id, used=False).count()
        if current_user.invite_quota > current_invites:
            token = str(uuid.uuid4())
            invite_token = InviteToken(token=token, creator_user_id=current_user.user_id)
            db.session.add(invite_token)
            db.session.commit()

            invite_url = url_for('main.register', token=token, _external=True, _scheme='https')

            send_invite_email(email, invite_url)

            flash('Invite sent successfully. The invite expires after 48 hours.', 'success')
        else:
            flash('You have reached your invite limit.', 'danger')
        return redirect(url_for('main.invites'))

    invites = InviteToken.query.filter_by(creator_user_id=current_user.user_id, used=False).all()
    current_invites_count = len(invites)
    remaining_invites = max(0, current_user.invite_quota - current_invites_count)

    return render_template('/login/invites.html', form=form, invites=invites, invite_quota=current_user.invite_quota, remaining_invites=remaining_invites)


def send_invite_email(email, invite_url):
    subject = "You're Invited!"
    html_content = render_template('login/invite_email.html', invite_url=invite_url)
    send_email(email, subject, html_content)


@bp.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    # Initialize the user creation form
    form = CreateUserForm()

    # Handle form submission
    if form.validate_on_submit():
        try:
            # Create a new user
            user = User(
                name=form.username.data,
                email=form.email.data.lower(),
                role='user',
                is_email_verified=True,  # Automatically set to True
                user_id=str(uuid4()),  # Generate a UUID for the user
                created=datetime.utcnow()
            )
            user.set_password(form.password.data)  # Set the user's password
            print(f"Debug: User created: {user}")
            db.session.add(user)
            db.session.commit()

            # Redirect to a success page
            flash('User created successfully.', 'success')
            return redirect(url_for('main.user_created'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')

    # Render the registration form
    return render_template('admin/create_user.html', form=form)

@bp.route('/admin/user_created')
@login_required
@admin_required
def user_created():
    return render_template('admin/create_user_done.html')

@bp.route('/api/current_user_role', methods=['GET'])
@login_required
def get_current_user_role():
    # print(f"Route: /api/current_user_role - {current_user.role}")
    return jsonify({'role': current_user.role}), 200

@bp.route('/api/check_username', methods=['POST'])
@login_required
def check_username():
    # print(F"Route: /api/check_username - {current_user.name} - {current_user.role}")
    data = request.get_json()
    username = data.get('username')

    if not username:
        print(f"Check username: Missing username")
        return jsonify({"error": "Missing username parameter"}), 400
    print(f"Checking username: {username}")
    existing_user = User.query.filter(func.lower(User.name) == func.lower(username)).first()
    return jsonify({"exists": existing_user is not None})

@bp.route('/delete_avatar/<path:avatar_path>', methods=['POST'])
@login_required
def delete_avatar(avatar_path):
    
    full_avatar_path = os.path.join(current_app.static_folder, avatar_path)
    print(f"Route: /delete_avatar {full_avatar_path}")

    if os.path.exists(full_avatar_path):
        os.remove(full_avatar_path)
        flash(f'Avatar image {full_avatar_path} deleted successfully!')
        print(f"Avatar image {full_avatar_path} deleted successfully!")
    else:
        flash(f'Avatar image {full_avatar_path} not found.')

    return redirect(url_for('main.bot_generator'))

@bp.route('/settings_account', methods=['GET', 'POST'])
@login_required
def account():
    print("Route: /settings_account")

    user = User.query.filter_by(id=current_user.id).first()
    form = UserDetailForm(about=str(user.about))
    

    if form.validate_on_submit():
      
        try:
            db.session.commit()
            

            flash('Account details updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error updating account details: {e}")
            flash('Failed to update account details. Please try again.', 'error')

        return redirect(url_for('main.account'))

    return render_template('settings/settings_account.html', title='Account', form=form, user=user)

@bp.route('/settings_profile_edit', methods=['GET', 'POST'])
@login_required
def settings_profile_edit():
    print("Route: Settings profile edit")
    form = EditProfileForm()

    if form.validate_on_submit():
        file = form.avatar.data
        if file:
            # Ensure UPLOAD_FOLDER exists
            upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'avatars_users')
            if not os.path.exists(upload_folder):
                try:
                    # Safe check to avoid creating 'static' directly
                    os.makedirs(upload_folder, exist_ok=True)
                except Exception as e:
                    print(f"Error creating upload directory: {e}")
                    flash("Error processing request. Please try again.", 'error')
                    return redirect(url_for('main.settings_profile_edit'))

            old_avatarpath = current_user.avatarpath
            # Define old_thumbnailpath based on old_avatarpath
            if old_avatarpath and old_avatarpath != 'newstyle/avatar_default.jpg':
                old_thumbnailpath = os.path.splitext(old_avatarpath)[0] + '_thumbnail' + os.path.splitext(old_avatarpath)[1]
            else:
                old_thumbnailpath = None  # No old thumbnail to worry about

            filename = secure_filename(file.filename)
            uuid_filename = str(uuid4()) + '.' + filename.rsplit('.', 1)[1].lower()
            image_path = os.path.join(upload_folder, uuid_filename)
            file.save(image_path)

            # Image processing
            img = PILImage.open(image_path)
            img = square_image(img, 500)  # Assume square_image is correctly defined elsewhere
            img.save(image_path)

            img = PILImage.open(image_path)
            img = square_image(img, 50)
            thumbnail_path = os.path.splitext(image_path)[0] + '_thumbnail' + os.path.splitext(image_path)[1]
            img.save(thumbnail_path)

            # Delete old avatar and thumbnail if they exist
            if old_avatarpath and old_avatarpath != 'newstyle/avatar_default.jpg':
                try:
                    os.remove(os.path.join(upload_folder, os.path.basename(old_avatarpath)))
                    if old_thumbnailpath:  # Check if old_thumbnailpath was defined
                        os.remove(os.path.join(upload_folder, os.path.basename(old_thumbnailpath)))
                except Exception as e:
                    print(f"Error deleting old avatar: {e}")
                    flash("Error deleting old avatar. Please try again.", 'error')

            current_user.avatarpath = 'library/avatars_users/' + uuid_filename
        else:
            if not current_user.avatarpath:
                current_user.avatarpath = 'newstyle/avatar_default.jpg'

        try:
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error updating profile: {e}")
            flash('Failed to update profile. Please try again.', 'error')

        return redirect(url_for('main.settings_profile_edit'))

    print("Form validation failed" if request.method == 'POST' else "Settings profile Form rendering")

    for field, errors in form.errors.items():
        for error in errors:
            print(f"Error in field '{getattr(form, field).label.text}': {error}")
            flash(f"Error in field '{getattr(form, field).label.text}': {error}", 'error')

    return render_template('settings/settings_profile_edit.html', form=form, avatarpath=current_user.avatarpath)

@bp.route('/settings_profile_view', methods=['GET'])
@login_required
def settings_profile_view():
    print("Route: Settings profile view")
    return render_template('settings/settings_profile_view.html')

@bp.route('/settings_password', methods=['GET', 'POST'])
@login_required
def account_pw():
    form = UserPasswordForm()
    # print("Request method:", request.method)  # Debug line
    user = User.query.get(current_user.id)

    if form.validate_on_submit():
        try:
            # print("Form data:", form.data)  # Debug line
            user.set_password(form.password.data)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            print('Password changed successfully for user ID:', current_user.id)
            return redirect(url_for('main.account_pw'))
        except Exception as e:
            db.session.rollback()
            print('An error occurred while changing the password:', str(e))
            flash('An error occurred. Please try again.', 'error')

    return render_template('settings/settings_password.html', title='Change Password', form=form, user=user)

@bp.route('/settings_panel', methods=['GET', 'POST'])
@login_required
@admin_required
def settings_panel():
    # print("Request method:", request.method)  # Debug line
    print("Route: /settings_panel")
    form = UserPreferencesForm()
    if request.method == 'POST' and form.validate_on_submit():
        # Ensure preferences exist
        if not current_user.preferences:
            current_user.preferences = UserPreference(user_id=current_user.id)
        
        current_user.preferences.items_per_page = form.items_per_page.data or current_user.preferences.items_per_page
        current_user.preferences.default_sort = form.default_sort.data or current_user.preferences.default_sort
        current_user.preferences.default_sort_order = form.default_sort_order.data or current_user.preferences.default_sort_order
        db.session.add(current_user.preferences)
        db.session.commit()
        flash('Your settings have been updated.', 'success')
        return redirect(url_for('main.restricted'))
    elif request.method == 'GET':
        # Ensure preferences exist
        if not current_user.preferences:
            current_user.preferences = UserPreference(user_id=current_user.id)
            db.session.add(current_user.preferences)
            db.session.commit()
        
        form.items_per_page.data = current_user.preferences.items_per_page
        form.default_sort.data = current_user.preferences.default_sort
        form.default_sort_order.data = current_user.preferences.default_sort_order

    return render_template('settings/settings_panel.html', form=form)




@bp.route('/admin/newsletter', methods=['GET', 'POST'])
@login_required
@admin_required
def newsletter():
    settings_record = GlobalSettings.query.first()
    enable_newsletter = settings_record.settings.get('enableNewsletterFeature', False) if settings_record else False

    if not enable_newsletter:
        flash('Newsletter feature is disabled.', 'warning')
        print("ADMIN NEWSLETTER: Newsletter feature is disabled.")
        return redirect(url_for('main.admin_dashboard'))
    print("ADMIN NEWSLETTER: Request method:", request.method)
    form = NewsletterForm()
    users = User.query.all()
    if form.validate_on_submit():
        recipients = form.recipients.data.split(',')
        print(f"ADMIN NEWSLETTER: Recipient list : {recipients}")
        
        msg = MailMessage(form.subject.data, sender=current_app.config['MAIL_DEFAULT_SENDER'])
        msg.body = form.content.data
        
        msg.recipients = recipients
        try:
            print(f"ADMIN NEWSLETTER: Newsletter sent")
            mail.send(msg)
            flash('Newsletter sent successfully!', 'success')
        except Exception as e:
            flash(str(e), 'error')
        return redirect(url_for('main.newsletter'))
    return render_template('admin/newsletter.html', title='Newsletter', form=form, users=users)


@bp.route('/admin/whitelist', methods=['GET', 'POST'])
@login_required
@admin_required
def whitelist():
    form = WhitelistForm()
    if form.validate_on_submit():
        email = form.email.data
        new_whitelist = Whitelist(email=email)
        db.session.add(new_whitelist)
        try:
            db.session.commit()
            flash('The email was successfully added to the whitelist!', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('The email is already in the whitelist!', 'danger')
        return redirect(url_for('main.whitelist'))
    whitelist = Whitelist.query.all()
    return render_template('admin/whitelist.html', title='Whitelist', whitelist=whitelist, form=form)



@bp.route('/admin/user_manager', methods=['GET', 'POST'])
@login_required
@admin_required
def usermanager():
    print("ADMIN USRMGR: username: Request method:", request.method)
    form = UserManagementForm()
    users_query = User.query.order_by(User.name).all()
    form.user_id.choices = [(user.id, user.name) for user in users_query]
    print(f"ADMIN USRMGR: User list : {users_query}")
    # Pre-populate the form when the page loads or re-populate upon validation failure
    if request.method == 'GET' or not form.validate_on_submit():
        # You could also use a default user here or based on some criteria
        default_user_id = request.args.get('user_id', 3)  # Example of getting a user_id from query parameters
        default_user = User.query.get(default_user_id)
        if default_user:
            form.user_id.data = default_user.id
            form.name.data = default_user.name
            form.email.data = default_user.email
            form.role.data = default_user.role
            form.state.data = default_user.state
            form.is_email_verified.data = default_user.is_email_verified
            form.about.data = default_user.about  # Pre-populate the 'about' field

    else:
        # This block handles the form submission for both updating and deleting users
        print(f"ADMIN USRMGR: Form data: {form.data}")
        user_id = form.user_id.data
        user = User.query.get(user_id)
        if not user:
            flash(f'User not found with ID: {user_id}', 'danger')
            return redirect(url_for('.usermanager'))  # Make sure the redirect is correct

        if form.submit.data:
            # Update user logic
            try:
                user.name = form.name.data or user.name
                user.email = form.email.data or user.email
                user.role = form.role.data or user.role
                user.state = form.state.data if form.state.data is not None else user.state
                user.is_email_verified = form.is_email_verified.data
                user.about = form.about.data
                print(f"ADMIN USRMGR: User updated: {user} about field : {user.about}")
                db.session.commit()
                flash('User updated successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Database error on update: {e}', 'danger')

        elif form.delete.data:
            # Delete user logic
            try:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Database error on delete: {e}', 'danger')

    return render_template('admin/user_manager.html', form=form, users=users_query)


@bp.route('/get_user/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        user_data = {
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'state': user.state,
            'about': user.about,
            'is_email_verified': user.is_email_verified
        }
        return jsonify(user_data)
    else:
        print(f"User not found with id: {user_id}")
        return jsonify({'error': 'User not found'}), 404


@bp.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_settings():
    if request.method == 'POST':
        new_settings = request.json

        settings_record = GlobalSettings.query.first()
        if not settings_record:
            settings_record = GlobalSettings(settings={})
            db.session.add(settings_record)
        
        settings_record.settings = new_settings
        settings_record.last_updated = datetime.utcnow()
        db.session.commit()
        cache.delete('global_settings')

        flash('HackPlanet.EU Settings updated successfully, Captain!', 'success')
        return jsonify({'message': 'Settings updated successfully'}), 200

    else:  # GET request
        settings_record = GlobalSettings.query.first()
        current_settings = settings_record.settings if settings_record else {}
        # Convert settings to the appropriate format for the template if necessary
        return render_template('admin/admin_settings.html', current_settings=current_settings)


@bp.route('/admin/status_page')
@login_required
@admin_required
def admin_status_page():
    print("Route: /admin/status_page")
    settings_record = GlobalSettings.query.first()
    enable_server_status = settings_record.settings.get('enableServerStatusFeature', False) if settings_record else False

    if not enable_server_status:
        flash('Server Status feature is disabled.', 'warning')
        return redirect(url_for('main.admin_dashboard'))
    
    uptime = datetime.now() - app_start_time
    config_values = {item: getattr(Config, item) for item in dir(Config) if not item.startswith("__")}
    
    
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except Exception as e:
        ip_address = 'Unavailable'
        print(f"Error retrieving IP address: {e}")
    
    system_info = {
        'OS': platform.system(),
        'OS Version': platform.version(),
        'Python Version': platform.python_version(),
        'Hostname': socket.gethostname(),
        'IP Address': socket.gethostbyname(socket.gethostname()),
        'Flask Port': request.environ.get('SERVER_PORT'),
        'Uptime': str(uptime),
        'Current Time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return render_template('admin/status_page.html', config_values=config_values, system_info=system_info, app_version=app_version)

@bp.route('/admin/manage_invites', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_invites():

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        invites_number = int(request.form.get('invites_number'))

        user = User.query.filter_by(user_id=user_id).first()
        if user:
            user.invite_quota += invites_number
            db.session.commit()
            flash('Invites updated successfully.', 'success')
        else:
            flash('User not found.', 'error')

    users = User.query.all()
    return render_template('admin/manage_invites.html', users=users)

@bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    pass
    return render_template('admin/admin_dashboard.html')


































@bp.route('/ctf')
def ctf_home():
    return render_template('site/ctf.html')


@bp.route('/ctf/leaderboard')
def leaderboard():
    # Fetch user scores from the database
    print("Fetching user scores from the database...")
    users = User.query.with_entities(User.name, User.score_total, User.avatarpath).order_by(User.score_total.desc()).all()
    
    # Debug print to verify fetched data
    if users:
        print(f"Users: {users} avatarpath: {users[0].avatarpath}")

    return render_template('site/leaderboard.html', users=users)


@bp.route('/ctf/hacking_labs')
def hacking_labs():
    # Fetch labs and their hosts from the database
    labs = Lab.query.options(joinedload(Lab.hosts).joinedload(Host.flags)).all()
    print(f"Labs: {labs} host: {labs[0].hosts} flags: {labs[0].hosts[0].flags}")
    # Check if the user is an admin
    is_admin = current_user.role == 'admin'

    # Instantiate the FlagSubmissionForm
    form = FlagSubmissionForm()

    return render_template('site/hacking_labs.html', labs=labs, is_admin=is_admin, form=form)

@bp.route('/ctf/challenges')
def challenges():
    # Fetch challenges from the database
    challenges = Challenge.query.all()
    return render_template('site/challenges.html', challenges=challenges)

@bp.route('/admin/lab_editor/<int:lab_id>', methods=['GET', 'POST'])
@bp.route('/admin/lab_editor', methods=['GET', 'POST'])
@login_required
@admin_required
def lab_editor(lab_id=None):
    form = LabForm()
    lab = Lab.query.get(lab_id) if lab_id else None

    if form.validate_on_submit():
        try:
            if lab:
                lab.name = form.name.data
                lab.image = form.image.data
                lab.description = form.description.data
            else:
                lab = Lab(
                    name=form.name.data,
                    image=form.image.data,
                    description=form.description.data,
                    date_created=datetime.utcnow()
                )
                db.session.add(lab)
            
            db.session.commit()
            flash('Lab saved successfully.', 'success')
            return redirect(url_for('main.lab_manager'))
        except Exception as e:
            db.session.rollback()
            print(f"Error saving lab: {str(e)}")
            flash('An error occurred while saving the lab. Please try again.', 'danger')

    if lab:
        form.name.data = lab.name
        form.image.data = lab.image
        form.description.data = lab.description

    return render_template('admin/lab_editor.html', form=form, lab=lab)

@bp.route('/admin/lab_manager', methods=['GET'])
@login_required
@admin_required
def lab_manager():
    print("Entered lab_manager route")
    labs = Lab.query.all()
    csrf_form = CsrfProtectForm()
    return render_template('admin/lab_manager.html', labs=labs, form=csrf_form)

@bp.route('/admin/delete_lab/<int:lab_id>', methods=['POST'])
@login_required
@admin_required
def delete_lab(lab_id):
    lab = Lab.query.get(lab_id)
    if lab:
        db.session.delete(lab)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({
            'success': False,
            'message': 'Lab not found'
        }), 404


@bp.route('/ctf/submit_flag', methods=['POST'])
def submit_flag():
    print("Entered submit_flag route")
    form = FlagSubmissionForm()
    print(f"submit flag Form data: {form.data}")

    print(f"Received flag: {form.flag.data}, host_id: {form.host_id.data}, flag_type: {form.flag_type.data}")
    if form.validate_on_submit():
        flag = form.flag.data
        host_id = form.host_id.data
        flag_type = form.flag_type.data

        print(f"Form submitted with flag: {flag}, host_id: {host_id}, flag_type: {flag_type}")

        try:
            # Retrieve the flag from the database
            print("Retrieving flag record from the database...")
            flag_record = Flag.query.filter_by(host_id=host_id, type=flag_type).first()
            print(f"Flag record retrieved: {flag_record}")

            if flag_record and flag_record.uuid == flag:
                print("Flag is correct.")
                # Flag is correct, update user progress and score
                user_progress = UserProgress.query.filter_by(user_id=current_user.id).first()
                if not user_progress:
                    user_progress = UserProgress(user_id=current_user.id, obtained_flags={}, score_total=0)
                    print("New user progress created.")

                obtained_flags = user_progress.obtained_flags or {}
                if flag_record.uuid not in obtained_flags:
                    print("Flag has not been submitted before. Updating progress and score.")
                    obtained_flags[flag_record.uuid] = True
                    user_progress.obtained_flags = obtained_flags
                    user_progress.score_total += flag_record.point_value
                    current_user.score_total += flag_record.point_value

                    db.session.add(user_progress)
                    db.session.commit()

                    print("User progress and score updated successfully.")
                    flash('Flag submitted successfully!', 'success')
                else:
                    print("Flag has already been submitted.")
                    flash('Flag has already been submitted.', 'warning')
            else:
                print("Invalid flag.")
                flash('Invalid flag.', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"An error occurred: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')

    print("Exiting submit_flag route")
    return redirect(url_for('main.hacking_labs'))




@bp.route('/ctf/submit_flag_api', methods=['GET'])
def submit_flag_api():
    flag = request.args.get('flag')
    flag_type = request.args.get('flag_type')
    host_id = request.args.get('host_id')

    if not flag or not flag_type or not host_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    print(f"Received flag: {flag}, host_id: {host_id}, flag_type: {flag_type}")
    flag_record = Flag.query.filter_by(host_id=host_id, type=flag_type).first()

    try:
        if flag_record and flag_record.uuid == flag:
            user_progress = UserProgress.query.filter_by(user_id=current_user.id).first()
            if not user_progress:
                user_progress = UserProgress(user_id=current_user.id, obtained_flags={}, score_total=0)

            obtained_flags = user_progress.obtained_flags or {}
            if flag_record.uuid not in obtained_flags:
                obtained_flags[flag_record.uuid] = True
                user_progress.obtained_flags = obtained_flags
                user_progress.score_total += flag_record.point_value
                current_user.score_total += flag_record.point_value

                db.session.add(user_progress)
                db.session.commit()

            return jsonify({'host_id': host_id, 'flag_type': flag_type, 'result': 'passed'})
        else:
            return jsonify({'error': 'Invalid flag'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'host_id': host_id, 'flag_type': flag_type, 'result': 'failed'})