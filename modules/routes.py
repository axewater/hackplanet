# modules/routes.py
import sys,ast, uuid, json, random, requests, html, os, re, shutil, traceback, time, schedule, os, platform, tempfile, socket, logging
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
    UserPasswordForm, UserDetailForm, EditProfileForm, NewsletterForm, WhitelistForm, EditUserForm, ChallengeForm,
    UserManagementForm, CsrfProtectForm, LoginForm, ResetPasswordRequestForm, RegistrationForm, HostForm,
    CreateUserForm, UserPreferencesForm, InviteForm, CsrfForm, LabForm, FlagSubmissionForm, ChallengeSubmissionForm,
    QuizForm, QuestionForm
)

from modules.models import (
    User, Whitelist, UserPreference, GlobalSettings, InviteToken, Lab, Challenge, Host, 
    Flag, UserProgress, FlagsObtained, ChallengesObtained, Quiz, Question, UserQuizProgress
)
from modules.utilities import (
    admin_required, _authenticate_and_redirect, square_image, send_email, send_password_reset_email
)
from modules.azure_utils import get_vm_status, start_vm, stop_vm, restart_vm


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
            logging.info("Default email added to Whitelist.")
    except IntegrityError:
        db.session.rollback()
        logging.info('Default email already exists in Whitelist.')
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.info(f'error adding default email to Whitelist: {e}')

    # Upgrade first user to admin
    try:
        user = User.query.get(1)
        if user and user.role != 'admin':
            user.role = 'admin'
            user.is_email_verified = True
            db.session.commit()
            logging.info(f"User '{user.name}' (ID: 1) upgraded to admin.")
        elif not user:
            logging.info("No user with ID 1 found in the database.")
        else:
            logging.info("User with ID 1 already has admin role.")
    except IntegrityError:
        db.session.rollback()
        logging.info('error while trying to upgrade user to admin.')
    except SQLAlchemyError as e:
        db.session.rollback()
        logging.info(f'error upgrading user to admin: {e}')

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
    logging.info("Route: /restricted")
    return render_template('site/restricted_area.html', title='Restricted Area')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.restricted'))

    logging.info("Route: /login")
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
                logging.info(f"Error: Attempted login to disabled account - User: {username}")
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
    logging.info("Route: /register")

    # Attempt to get the invite token from the query parameters
    invite_token_from_url = request.args.get('token')
    logging.info(f"Invite token from URL: {invite_token_from_url}")
    invite = None
    if invite_token_from_url:
        invite = InviteToken.query.filter_by(token=invite_token_from_url, used=False).first()
        logging.info(f"Invite found: {invite}")
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
                logging.info(f"/register: Email already in use - {email_address}")
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
                logging.info(f"/register: User already exists - {form.username.data}")
                flash('User already exists. Please Log in.')
                return redirect(url_for('main.register'))

            user_uuid = str(uuid4())
            existing_uuid = User.query.filter_by(user_id=user_uuid).first()
            if existing_uuid is not None:
                logging.info("/register: UUID collision detected.")
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
            logging.info(f"Invite Token from URL: {invite_token_from_url}")

            if invite:
                logging.info(f"Found valid invite: {invite.token}, expires at: {invite.expires_at}, used: {invite.used}")
                invite.used = True
                db.session.commit()
            else:
                logging.info("No valid invite found or invite expired/used.")
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
            logging.info(f"IntegrityError occurred: {e}")
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

            # Add the invited email to the whitelist
            whitelist_entry = Whitelist(email=email)
            db.session.add(whitelist_entry)

            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash('This email is already whitelisted.', 'info')
            else:
                invite_url = url_for('main.register', token=token, _external=True, _scheme='https')
                send_invite_email(email, invite_url)
                flash('Invite sent successfully and email added to whitelist. The invite expires after 48 hours.', 'success')
        else:
            flash('You have reached your invite limit.', 'danger')
        return redirect(url_for('main.invites'))

    invites = InviteToken.query.filter_by(creator_user_id=current_user.user_id, used=False).all()
    current_invites_count = len(invites)
    remaining_invites = max(0, current_user.invite_quota - current_invites_count)

    return render_template('/login/invites.html', form=form, invites=invites, invite_quota=current_user.invite_quota, remaining_invites=remaining_invites)

@bp.route('/delete_invite/<int:invite_id>', methods=['POST'])
@login_required
def delete_invite(invite_id):
    invite = InviteToken.query.filter_by(id=invite_id, creator_user_id=current_user.user_id, used=False).first()
    if invite:
        try:
            db.session.delete(invite)
            db.session.commit()
            flash('Invite deleted successfully.', 'success')
            return jsonify({'success': True, 'message': 'Invite deleted successfully.'})
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting invite: {str(e)}")
            return jsonify({'success': False, 'message': 'An error occurred while deleting the invite.'}), 500
    else:
        return jsonify({'success': False, 'message': 'Invalid invite or you do not have permission to delete it.'}), 404




def send_invite_email(email, invite_url):
    subject = "You're Invited to Join HackPlanet.EU!"
    html_content = render_template('login/invite_email.html', invite_url=invite_url, email=email)
    send_email(email, subject, html_content)


@bp.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    form = CreateUserForm()

    if form.validate_on_submit():
        try:
            user = User(
                name=form.username.data,
                email=form.email.data.lower(),
                role='user',
                is_email_verified=True,
                user_id=str(uuid4()),
                created=datetime.utcnow()
            )
            user.set_password(form.password.data)
            logging.info(f"Debug: User created: {user}")
            db.session.add(user)
            db.session.commit()

            flash('User created successfully.', 'success')
            return redirect(url_for('main.usermanager'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')

    return render_template('admin/create_user.html', form=form)

@bp.route('/admin/user_created')
@login_required
@admin_required
def user_created():
    return render_template('admin/create_user_done.html')

@bp.route('/api/current_user_role', methods=['GET'])
@login_required
def get_current_user_role():
    # logging.info(f"Route: /api/current_user_role - {current_user.role}")
    return jsonify({'role': current_user.role}), 200

@bp.route('/api/check_username', methods=['POST'])
@login_required
def check_username():
    # logging.info(F"Route: /api/check_username - {current_user.name} - {current_user.role}")
    data = request.get_json()
    username = data.get('username')

    if not username:
        logging.info(f"Check username: Missing username")
        return jsonify({"error": "Missing username parameter"}), 400
    logging.info(f"Checking username: {username}")
    existing_user = User.query.filter(func.lower(User.name) == func.lower(username)).first()
    return jsonify({"exists": existing_user is not None})

@bp.route('/delete_avatar/<path:avatar_path>', methods=['POST'])
@login_required
def delete_avatar(avatar_path):
    
    full_avatar_path = os.path.join(current_app.static_folder, avatar_path)
    logging.info(f"Route: /delete_avatar {full_avatar_path}")

    if os.path.exists(full_avatar_path):
        os.remove(full_avatar_path)
        flash(f'Avatar image {full_avatar_path} deleted successfully!')
        logging.info(f"Avatar image {full_avatar_path} deleted successfully!")
    else:
        flash(f'Avatar image {full_avatar_path} not found.')

    return redirect(url_for('main.bot_generator'))

@bp.route('/settings_account', methods=['GET', 'POST'])
@login_required
def account():
    logging.info("Route: /settings_account")

    user = User.query.filter_by(id=current_user.id).first()
    form = UserDetailForm(about=str(user.about))
    

    if form.validate_on_submit():
      
        try:
            db.session.commit()
            

            flash('Account details updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            logging.info(f"Error updating account details: {e}")
            flash('Failed to update account details. Please try again.', 'error')

        return redirect(url_for('main.account'))

    return render_template('settings/settings_account.html', title='Account', form=form, user=user)

@bp.route('/settings_profile_edit', methods=['GET', 'POST'])
@login_required
def settings_profile_edit():
    logging.info("Route: Settings profile edit")
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
                    logging.info(f"Error creating upload directory: {e}")
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
                    logging.info(f"Error deleting old avatar: {e}")
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
            logging.info(f"Error updating profile: {e}")
            flash('Failed to update profile. Please try again.', 'error')

        return redirect(url_for('main.settings_profile_edit'))

    logging.info("Form validation failed" if request.method == 'POST' else "Settings profile Form rendering")

    for field, errors in form.errors.items():
        for error in errors:
            logging.info(f"Error in field '{getattr(form, field).label.text}': {error}")
            flash(f"Error in field '{getattr(form, field).label.text}': {error}", 'error')

    return render_template('settings/settings_profile_edit.html', form=form, avatarpath=current_user.avatarpath)

@bp.route('/settings_profile_view', methods=['GET'])
@login_required
def settings_profile_view():
    logging.info("Route: Settings profile view")
    return render_template('settings/settings_profile_view.html')

@bp.route('/settings_password', methods=['GET', 'POST'])
@login_required
def account_pw():
    form = UserPasswordForm()
    # logging.info("Request method:", request.method)  # Debug line
    user = User.query.get(current_user.id)

    if form.validate_on_submit():
        try:
            # logging.info("Form data:", form.data)  # Debug line
            user.set_password(form.password.data)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            logging.info('Password changed successfully for user ID:', current_user.id)
            return redirect(url_for('main.account_pw'))
        except Exception as e:
            db.session.rollback()
            logging.info('An error occurred while changing the password:', str(e))
            flash('An error occurred. Please try again.', 'error')

    return render_template('settings/settings_password.html', title='Change Password', form=form, user=user)

@bp.route('/settings_panel', methods=['GET', 'POST'])
@login_required
@admin_required
def settings_panel():
    # logging.info("Request method:", request.method)  # Debug line
    logging.info("Route: /settings_panel")
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
        logging.info("ADMIN NEWSLETTER: Newsletter feature is disabled.")
        return redirect(url_for('main.admin_dashboard'))
    logging.info("ADMIN NEWSLETTER: Request method:", request.method)
    form = NewsletterForm()
    users = User.query.all()
    if form.validate_on_submit():
        recipients = form.recipients.data.split(',')
        logging.info(f"ADMIN NEWSLETTER: Recipient list : {recipients}")
        
        msg = MailMessage(form.subject.data, sender=current_app.config['MAIL_DEFAULT_SENDER'])
        msg.body = form.content.data
        
        msg.recipients = recipients
        try:
            logging.info(f"ADMIN NEWSLETTER: Newsletter sent")
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
    logging.info("ADMIN USRMGR: username: Request method:", request.method)
    form = UserManagementForm()
    users_query = User.query.order_by(User.name).all()
    form.user_id.choices = [(user.id, user.name) for user in users_query]
    logging.info(f"ADMIN USRMGR: User list : {users_query}")
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
        logging.info(f"ADMIN USRMGR: Form data: {form.data}")
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
                logging.info(f"ADMIN USRMGR: User updated: {user} about field : {user.about}")
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
        logging.info(f"User not found with id: {user_id}")
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
    logging.info("Route: /admin/status_page")
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
        logging.info(f"Error retrieving IP address: {e}")
    
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
    logging.info("Fetching user scores from the database...")
    users = db.session.query(User, func.sum(UserQuizProgress.score).label('quiz_score')).outerjoin(UserQuizProgress).group_by(User.id).order_by((User.score_total + func.coalesce(func.sum(UserQuizProgress.score), 0)).desc()).all()
    
    # Prepare user data for the template
    user_data = []
    for user, quiz_score in users:
        total_score = user.score_total + (quiz_score or 0)
        user_data.append({
            'name': user.name,
            'score_total': total_score,
            'avatarpath': user.avatarpath
        })
    
    # Debug logging.info to verify fetched data
    if user_data:
        logging.info(f"Users: {user_data}")

    return render_template('site/leaderboard.html', users=user_data)




@bp.route('/ctf/challenges')
def challenges():
    # Fetch challenges from the database
    challenges = Challenge.query.all()
    for challenge in challenges:
        if challenge.html_link:
            challenge.image = challenge.html_link
        else:
            challenge.image = 'default_challenge_image.jpg'
    form = ChallengeSubmissionForm()
    return render_template('site/challenges.html', challenges=challenges, form=form)

@bp.route('/ctf/submit_challenge_flag', methods=['POST'])
@login_required
def submit_challenge_flag():
    form = ChallengeSubmissionForm()
    if form.validate_on_submit():
        challenge = Challenge.query.get(form.challenge_id.data)
        if challenge and challenge.flag_uuid == form.flag.data:
            # Check if the user has already completed this challenge
            if not ChallengesObtained.query.filter_by(user_id=current_user.id, challenge_id=challenge.id).first():
                # Add points to user's score
                current_user.score_total += challenge.point_value
                # Mark challenge as completed
                completed_challenge = ChallengesObtained(user_id=current_user.id, challenge_id=challenge.id)
                db.session.add(completed_challenge)
                db.session.commit()
                flash('Congratulations! You solved the challenge.', 'success')
            else:
                flash('You have already completed this challenge.', 'info')
        else:
            flash('Incorrect flag. Try again.', 'error')
    return redirect(url_for('main.challenges'))

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
            logging.info(f"Error saving lab: {str(e)}")
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
    logging.info("Entered lab_manager route")
    labs = Lab.query.all()
    csrf_form = CsrfProtectForm()
    return render_template('admin/lab_manager.html', labs=labs, form=csrf_form)

@bp.route('/admin/delete_lab/<int:lab_id>', methods=['POST'])
@login_required
@admin_required
def delete_lab(lab_id):
    lab = Lab.query.get(lab_id)
    if lab:
        try:
            db.session.delete(lab)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting lab: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'An error occurred while deleting the lab'
            }), 500
    else:
        return jsonify({
            'success': False,
            'message': 'Lab not found'
        }), 404

@bp.route('/admin/challenge_manager', methods=['GET'])
@login_required
@admin_required
def challenge_manager():
    logging.info("Entered challenge_manager route")
    challenges = Challenge.query.all()
    csrf_form = CsrfProtectForm()
    return render_template('admin/challenge_manager.html', challenges=challenges, form=csrf_form)

@bp.route('/admin/delete_challenge/<int:challenge_id>', methods=['POST'])
@login_required
@admin_required
def delete_challenge(challenge_id):
    challenge = Challenge.query.get(challenge_id)
    if challenge:
        db.session.delete(challenge)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({
            'success': False,
            'message': 'Challenge not found'
        }), 404

@bp.route('/admin/challenge_editor/<int:challenge_id>', methods=['GET', 'POST'])
@bp.route('/admin/challenge_editor', methods=['GET', 'POST'])
@login_required
@admin_required
def challenge_editor(challenge_id=None):
    form = ChallengeForm()
    challenge = Challenge.query.get(challenge_id) if challenge_id else None

    if form.validate_on_submit():
        try:
            if challenge:
                challenge.name = form.name.data
                challenge.description = form.description.data
                challenge.flag_uuid = form.flag_uuid.data or str(uuid4())
                challenge.html_link = form.html_link.data
                challenge.point_value = form.point_value.data
            else:
                challenge = Challenge(
                    name=form.name.data,
                    description=form.description.data,
                    flag_uuid=form.flag_uuid.data or str(uuid4()),
                    html_link=form.html_link.data,
                    point_value=form.point_value.data
                )
                db.session.add(challenge)
            
            db.session.commit()
            flash('Challenge saved successfully.', 'success')
            return redirect(url_for('main.challenge_manager'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error saving challenge: {str(e)}")
            flash('An error occurred while saving the challenge. Please try again.', 'danger')

    if challenge:
        form.name.data = challenge.name
        form.description.data = challenge.description
        form.flag_uuid.data = challenge.flag_uuid
        form.html_link.data = challenge.html_link
        form.point_value.data = challenge.point_value

    return render_template('admin/challenge_editor.html', form=form, challenge=challenge)



@bp.route('/ctf/submit_flag_api', methods=['GET'])
def submit_flag_api():
    flag = request.args.get('flag')
    flag_type = request.args.get('flag_type')
    host_id = request.args.get('host_id')

    if not flag or not flag_type or not host_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    logging.info(f"Received flag: {flag}, host_id: {host_id}, flag_type: {flag_type}")
    try:
        flag_record = Flag.query.filter_by(host_id=host_id, type=flag_type).first()
    except Exception as e:
        logging.error(f"Error retrieving flag record: {str(e)}")
        return jsonify({'error': 'An error occurred while retrieving the flag record'}), 500

    try:
        if flag_record and flag_record.uuid == flag:
            try:
                user_progress = UserProgress.query.filter_by(user_id=current_user.id).first()
                if not user_progress:
                    user_progress = UserProgress(user_id=current_user.id, score_total=0)
                    db.session.add(user_progress)
            except Exception as e:
                logging.error(f"Error retrieving or creating user progress: {str(e)}")
                return jsonify({'error': 'An error occurred while processing user progress'}), 500

            try:
                flag_obtained = FlagsObtained.query.filter_by(user_id=current_user.id, flag_id=flag_record.id).first()
            except Exception as e:
                logging.error(f"Error checking if flag is already obtained: {str(e)}")
                return jsonify({'error': 'An error occurred while checking if the flag is already obtained'}), 500

            if not flag_obtained:
                try:
                    flag_obtained = FlagsObtained(user_id=current_user.id, flag_id=flag_record.id)
                    db.session.add(flag_obtained)

                    user_progress.score_total += flag_record.point_value
                    current_user.score_total += flag_record.point_value

                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    logging.error(f"Error updating user progress and score: {str(e)}")
                    return jsonify({'error': 'An error occurred while updating user progress and score'}), 500

                return jsonify({'host_id': host_id, 'flag_type': flag_type, 'result': 'passed'})
            else:
                return jsonify({'error': 'Sorry, you have already submitted this flag'}), 400
        else:
            return jsonify({'error': 'Invalid flag'}), 400
    except Exception as e:
        logging.error(f"Error processing flag submission: {str(e)}")
        return jsonify({'error': 'An error occurred while processing the flag submission'}), 500

    return jsonify({'host_id': host_id, 'flag_type': flag_type, 'result': 'failed'})

@bp.route('/ctf/submit_challenge_flag_api', methods=['GET'])
@login_required
def submit_challenge_flag_api():
    flag = request.args.get('flag')
    challenge_id = request.args.get('challenge_id')

    if not flag or not challenge_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    logging.info(f"Received challenge flag: {flag}, challenge_id: {challenge_id}")
    try:
        challenge = Challenge.query.get(challenge_id)
        if not challenge:
            return jsonify({'error': 'Challenge not found'}), 404

        if challenge.flag_uuid == flag:
            challenge_obtained = ChallengesObtained.query.filter_by(user_id=current_user.id, challenge_id=challenge.id).first()
            if not challenge_obtained:
                challenge_obtained = ChallengesObtained(user_id=current_user.id, challenge_id=challenge.id)
                db.session.add(challenge_obtained)

                current_user.score_total += challenge.point_value
                db.session.commit()

                return jsonify({'challenge_id': challenge_id, 'result': 'passed'})
            else:
                return jsonify({'error': 'You have already completed this challenge'}), 400
        else:
            return jsonify({'error': 'Invalid flag'}), 400
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error processing challenge flag submission: {str(e)}")
        return jsonify({'error': 'An error occurred while processing the challenge flag submission'}), 500

@bp.route('/ctf/quizzes')
@login_required
def quizzes():
    quizzes = Quiz.query.all()
    user_progress = UserQuizProgress.query.filter_by(user_id=current_user.id).all()
    completed_quizzes = {progress.quiz_id: progress.score for progress in user_progress if progress.completed}
    return render_template('site/quizzes.html', quizzes=quizzes, completed_quizzes=completed_quizzes)

@bp.route('/ctf/take_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    user_progress = UserQuizProgress.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first()

    if user_progress and user_progress.completed:
        flash('You have already completed this quiz.', 'info')
        return redirect(url_for('main.quiz_results', quiz_id=quiz_id))

    if request.method == 'POST':
        score = 0
        for question in quiz.questions:
            answer = request.form.get(f'question_{question.id}')
            if answer == question.correct_answer:
                score += question.points
        
        if not user_progress:
            user_progress = UserQuizProgress(user_id=current_user.id, quiz_id=quiz_id)
        
        user_progress.score = score
        user_progress.completed = True
        user_progress.completed_at = datetime.utcnow()
        
        db.session.add(user_progress)
        db.session.commit()
        
        flash(f'Quiz completed! Your score: {score}', 'success')
        return redirect(url_for('main.quiz_results', quiz_id=quiz_id))
    
    return render_template('site/take_quiz.html', quiz=quiz)

@bp.route('/ctf/quiz_results/<int:quiz_id>')
@login_required
def quiz_results(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    user_progress = UserQuizProgress.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first_or_404()
    return render_template('site/quiz_results.html', quiz=quiz, user_progress=user_progress)

@bp.route('/ctf/hacking_labs')
def hacking_labs():
    # Fetch labs and their hosts from the database
    labs = Lab.query.options(joinedload(Lab.hosts).joinedload(Host.flags)).all()
    logging.info(f"Labs: {labs} host: {labs[0].hosts} flags: {labs[0].hosts[0].flags}")
    # Check if the user is an admin
    is_admin = current_user.role == 'admin'

    # Instantiate the FlagSubmissionForm
    form = FlagSubmissionForm()

    return render_template('site/hacking_labs.html', labs=labs, is_admin=is_admin, form=form)

@bp.route('/ctf/user_progress')
@login_required
def user_progress():
    # Fetch completed challenges
    completed_challenges = ChallengesObtained.query.filter_by(user_id=current_user.id).all()
    
    # Fetch obtained flags
    obtained_flags = FlagsObtained.query.filter_by(user_id=current_user.id).all()
    
    # Calculate total score
    total_score = current_user.score_total
    
    return render_template('site/user_progress.html', 
                           completed_challenges=completed_challenges,
                           obtained_flags=obtained_flags,
                           total_score=total_score)

@bp.route('/admin/host_manager', methods=['GET'])
@login_required
@admin_required
def host_manager():
    hosts = Host.query.all()
    csrf_form = CsrfProtectForm()
    return render_template('admin/host_manager.html', hosts=hosts, form=csrf_form)

@bp.route('/admin/host_editor/<int:host_id>', methods=['GET', 'POST'])
@bp.route('/admin/host_editor', methods=['GET', 'POST'])
@login_required
@admin_required
def host_editor(host_id=None):
    form = HostForm()
    labs = Lab.query.all()
    host = Host.query.get(host_id) if host_id else None

    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                if host:
                    form.populate_obj(host)
                else:
                    host = Host()
                    form.populate_obj(host)
                    db.session.add(host)
                
                host.lab_id = form.lab_id.data
                logging.info(f"Debug: Lab ID being set: {host.lab_id}")
                db.session.commit()
                return jsonify({'success': True, 'message': 'Host saved successfully.'})
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error saving host: {str(e)}")
                return jsonify({'success': False, 'message': 'An error occurred while saving the host.', 'errors': form.errors}), 400
        else:
            logging.error(f"Form validation failed: {form.errors}")
            return jsonify({'success': False, 'message': 'Validation failed.', 'errors': form.errors}), 400

    if host:
        form = HostForm(obj=host)
        form.lab_id.data = host.lab_id
    
    return render_template('admin/host_editor.html', form=form, host=host, labs=labs)

@bp.route('/ctf/host_details/<int:host_id>')
@login_required
def host_details(host_id):
    host = Host.query.get_or_404(host_id)
    vm_status = get_vm_status(host.azure_vm_id) if host.azure_vm_id else None
    return render_template('site/host_details.html', host=host, vm_status=vm_status)

@bp.route('/ctf/start_vm/<int:host_id>', methods=['POST'])
@login_required
def start_vm_route(host_id):
    host = Host.query.get_or_404(host_id)
    if host.azure_vm_id:
        try:
            start_vm(host.azure_vm_id)
            flash('VM start initiated successfully.', 'success')
        except Exception as e:
            flash(f'Error starting VM: {str(e)}', 'error')
    
    else:
        flash('No Azure VM ID associated with this host.', 'error')
    return redirect(url_for('main.host_details', host_id=host_id))

@bp.route('/ctf/stop_vm/<int:host_id>', methods=['POST'])
@login_required
def stop_vm_route(host_id):
    host = Host.query.get_or_404(host_id)
    if host.azure_vm_id:
        try:
            stop_vm(host.azure_vm_id)
            flash('VM stop initiated successfully.', 'success')
        except Exception as e:
            flash(f'Error stopping VM: {str(e)}', 'error')
    else:
        flash('No Azure VM ID associated with this host.', 'error')
    return redirect(url_for('main.host_details', host_id=host_id))

@bp.route('/ctf/restart_vm/<int:host_id>', methods=['POST'])
@login_required
def restart_vm_route(host_id):
    host = Host.query.get_or_404(host_id)
    if host.azure_vm_id:
        try:
            restart_vm(host.azure_vm_id)
            flash('VM restart initiated successfully.', 'success')
        except Exception as e:
            flash(f'Error restarting VM: {str(e)}', 'error')
    else:
        flash('No Azure VM ID associated with this host.', 'error')
    return redirect(url_for('main.host_details', host_id=host_id))

@bp.route('/admin/delete_host/<int:host_id>', methods=['POST'])
@login_required
@admin_required
def delete_host(host_id):
    host = Host.query.get(host_id)
    if host:
        db.session.delete(host)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({
            'success': False,
            'message': 'Host not found'
        }), 404

@bp.route('/admin/quiz_manager')
@login_required
@admin_required
def quiz_manager():
    quizzes = Quiz.query.all()
    return render_template('admin/quiz_manager.html', quizzes=quizzes)

@bp.route('/admin/quiz_editor', methods=['GET', 'POST'])
@bp.route('/admin/quiz_editor/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def quiz_editor(quiz_id=None):
    form = QuizForm()
    quiz = Quiz.query.get(quiz_id) if quiz_id else None

    if form.validate_on_submit():
        if quiz:
            quiz.title = form.title.data
            quiz.description = form.description.data
            quiz.min_score = form.min_score.data
        else:
            quiz = Quiz(title=form.title.data, description=form.description.data, min_score=form.min_score.data)
            db.session.add(quiz)
        db.session.commit()
        flash('Quiz saved successfully.', 'success')
        return redirect(url_for('main.quiz_manager'))

    if quiz:
        form.title.data = quiz.title
        form.description.data = quiz.description
        form.min_score.data = quiz.min_score

    return render_template('admin/quiz_editor.html', form=form, quiz=quiz)

@bp.route('/admin/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get(quiz_id)
    if quiz:
        db.session.delete(quiz)
        db.session.commit()
        flash('Quiz deleted successfully.', 'success')
    else:
        flash('Quiz not found.', 'error')
    return redirect(url_for('main.quiz_manager'))

@bp.route('/admin/question_editor/<int:quiz_id>', methods=['GET', 'POST'])
@bp.route('/admin/question_editor/<int:quiz_id>/<int:question_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def question_editor(quiz_id, question_id=None):
    form = QuestionForm()
    quiz = Quiz.query.get_or_404(quiz_id)
    question = Question.query.get(question_id) if question_id else None

    if form.validate_on_submit():
        if question:
            question.question_text = form.question_text.data
            question.option_a = form.option_a.data
            question.option_b = form.option_b.data
            question.option_c = form.option_c.data
            question.option_d = form.option_d.data
            question.correct_answer = form.correct_answer.data
            question.points = form.points.data
        else:
            question = Question(
                quiz_id=quiz_id,
                question_text=form.question_text.data,
                option_a=form.option_a.data,
                option_b=form.option_b.data,
                option_c=form.option_c.data,
                option_d=form.option_d.data,
                correct_answer=form.correct_answer.data,
                points=form.points.data
            )
            db.session.add(question)
        db.session.commit()
        flash('Question saved successfully.', 'success')
        return redirect(url_for('main.quiz_editor', quiz_id=quiz_id))

    if question:
        form.question_text.data = question.question_text
        form.option_a.data = question.option_a
        form.option_b.data = question.option_b
        form.option_c.data = question.option_c
        form.option_d.data = question.option_d
        form.correct_answer.data = question.correct_answer
        form.points.data = question.points

    return render_template('admin/question_editor.html', form=form, quiz=quiz, question=question)

@bp.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@login_required
@admin_required
def delete_question(question_id):
    question = Question.query.get(question_id)
    if question:
        quiz_id = question.quiz_id
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully.', 'success')
        return redirect(url_for('main.quiz_editor', quiz_id=quiz_id))
    else:
        flash('Question not found.', 'error')
        return redirect(url_for('main.quiz_manager'))