# modules/routes.py
import sys,ast, uuid, json, random, requests, html, os, re, shutil, traceback, time, schedule, os, platform, tempfile, socket, logging, requests
from threading import Thread
import subprocess, mimetypes
from config import Config
from flask import Flask, render_template, flash, redirect, url_for, request, Blueprint, jsonify, session, abort, current_app, send_from_directory, send_file
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
from PIL import Image
from io import BytesIO

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
    QuizForm, QuestionForm, FlagForm, CourseForm
)

from modules.models import (
    User, Whitelist, UserPreference, GlobalSettings, InviteToken, Lab, Challenge, Host, 
    Flag, UserProgress, FlagsObtained, ChallengesObtained, Quiz, Question, UserQuizProgress, UserQuestionProgress, Course
)
from modules.utilities import (
    admin_required, _authenticate_and_redirect, square_image, send_email, send_password_reset_email, 
)
from modules.azure_utils import get_vm_status, check_azure_authentication, get_azure_cli_path
import logging

bp = Blueprint('main', __name__)



@bp.route('/ctf/test_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def test_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).order_by(Question.id).all()
    
    if 'current_question' not in session:
        session['current_question'] = 0
        session['results'] = []
        session['total_score'] = 0
    
    if request.method == 'POST':
        answer = request.form.get('answer')
        current_question = questions[session['current_question']]
        is_correct = answer == current_question.correct_answer
        if is_correct:
            session['total_score'] += current_question.points
        session['results'].append({
            'question': current_question.question_text,
            'user_answer': answer,
            'correct_answer': current_question.correct_answer,
            'is_correct': is_correct,
            'explanation': current_question.explanation
        })
        session['current_question'] += 1
        session.modified = True
        
        if session['current_question'] >= len(questions):
            results = session['results']
            total_score = session['total_score']
            session.pop('current_question', None)
            session.pop('results', None)
            session.pop('total_score', None)
            return render_template('site/test_quiz_results.html', quiz=quiz, results=results, total_score=total_score)
    
    if session['current_question'] < len(questions):
        question = questions[session['current_question']]
        return render_template('site/test_quiz.html', quiz=quiz, question=question, progress=session['current_question']+1, total=len(questions))
    
    # This should not happen, but just in case
    return redirect(url_for('main.quizzes'))


s = URLSafeTimedSerializer('YMecr3tK?IzzsSa@e!Zithpze') 
has_initialized_whitelist = False
has_upgraded_admin = False
has_initialized_setup = False
app_start_time = datetime.now()
app_version = '1.3.0'

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
        enable_newsletter = settings_record.settings.get('enableNewsletterFeature', False)
        enable_maintenance_mode = settings_record.settings.get('enableMaintenanceMode', False)
    else:
        # Default values if no settings_record is found
        show_logo = True
        show_help_button = True
        enable_web_links = True
        enable_server_status = True
        enable_newsletter = True
        enable_maintenance_mode = False

    return dict(
        show_logo=show_logo, 
        show_help_button=show_help_button, 
        enable_web_links=enable_web_links,
        enable_server_status=enable_server_status,
        enable_newsletter=enable_newsletter,
        enable_maintenance_mode=enable_maintenance_mode
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
                invited_by=invite.creator_user_id if invite else None
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            print(f"Invite Token from URL: {invite_token_from_url}")

            if invite:
                print(f"Found valid invite: {invite.token}, expires at: {invite.expires_at}, used: {invite.used}")
                invite.used = True
                invite.used_by = user.user_id
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

            # Always add or update the whitelist entry
            whitelist_entry = Whitelist.query.filter_by(email=email).first()
            if whitelist_entry:
                # Update existing entry
                whitelist_entry.email = email
            else:
                # Add new entry
                whitelist_entry = Whitelist(email=email)
                db.session.add(whitelist_entry)

            try:
                db.session.commit()
                invite_url = url_for('main.register', token=token, _external=True, _scheme='https')
                send_invite_email(email, invite_url)
                flash('Invite sent successfully and email added/updated in whitelist. The invite expires after 48 hours.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {str(e)}', 'error')
        else:
            flash('You have reached your invite limit.', 'danger')
        return redirect(url_for('main.invites'))

    invites = InviteToken.query.filter_by(creator_user_id=current_user.user_id).all()
    for invite in invites:
        if invite.used_by:
            invite.used_by_user = User.query.filter_by(user_id=invite.used_by).first()
    current_invites_count = len([invite for invite in invites if not invite.used])
    remaining_invites = max(0, current_user.invite_quota - current_invites_count)

    return render_template('/login/invites.html', form=form, invites=invites, invite_quota=current_user.invite_quota, remaining_invites=remaining_invites)

@bp.route('/delete_invite/<int:invite_id>', methods=['POST'])
@login_required
def delete_invite(invite_id):
    invite = InviteToken.query.filter_by(id=invite_id, creator_user_id=current_user.user_id).first()
    if invite:
        if invite.used:
            return jsonify({'success': False, 'message': 'Cannot delete a used invite.'}), 400
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
            print(f"Debug: User created: {user}")
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

@bp.route('/admin/whitelist/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_whitelist(id):
    whitelist_entry = Whitelist.query.get_or_404(id)
    db.session.delete(whitelist_entry)
    db.session.commit()
    flash('Email removed from whitelist successfully!', 'success')
    return redirect(url_for('main.whitelist'))



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

@bp.before_request
def check_maintenance_mode():
    settings_record = GlobalSettings.query.first()
    if settings_record and settings_record.settings.get('enableMaintenanceMode', False):
        if not current_user.is_authenticated or current_user.role != 'admin':
            if request.path.startswith('/ctf'):
                return render_template('maintenance.html'), 503


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

@bp.route('/admin/update_invites', methods=['POST'])
@login_required
@admin_required
def update_invites():
    data = request.json
    user_id = data.get('user_id')
    invite_change = data.get('invite_change')

    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    new_quota = max(0, user.invite_quota + invite_change)
    user.invite_quota = new_quota
    db.session.commit()

    return jsonify({'success': True, 'new_quota': new_quota})

@bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    pass
    return render_template('admin/admin_dashboard.html')

@bp.route('/admin/file_manager')
@login_required
@admin_required
def file_manager():
    return render_template('admin/file_manager.html')

@bp.route('/admin/media/list')
@login_required
@admin_required
def media_list():
    path = request.args.get('path', '/')
    full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path.lstrip('/'))
    
    if not os.path.exists(full_path) or not os.path.isdir(full_path):
        return jsonify({'error': 'Invalid path'}), 400

    files = []
    for item in os.listdir(full_path):
        item_path = os.path.join(full_path, item)
        is_dir = os.path.isdir(item_path)
        if is_dir or os.path.isfile(item_path):
            file_type = 'Folder' if is_dir else mimetypes.guess_type(item)[0] or 'Unknown'
            size = '' if is_dir else f"{os.path.getsize(item_path) / 1024:.2f} KB"
            files.append({
                'name': item,
                'path': os.path.join(path, item),
                'type': file_type,
                'size': size,
                'is_dir': is_dir
            })

    return jsonify({'files': files})

@bp.route('/admin/media/upload', methods=['POST'])
@login_required
@admin_required
def media_upload():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'}), 400
    
    path = request.form.get('path', '/')
    if path == '/':
        return jsonify({'success': False, 'message': 'Cannot upload to root directory'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path.lstrip('/'))
        
        if not os.path.exists(full_path):
            return jsonify({'success': False, 'message': 'Invalid path'}), 400
        
        file_path = os.path.join(full_path, filename)
        try:
            file.save(file_path)
            return jsonify({'success': True, 'message': 'File uploaded successfully'})
        except PermissionError:
            return jsonify({'success': False, 'message': 'Permission denied. Unable to save file.'}), 403
        except Exception as e:
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500
    
    return jsonify({'success': False, 'message': 'File upload failed'}), 400

@bp.route('/admin/media/thumbnail')
@login_required
@admin_required
def media_thumbnail():
    path = request.args.get('path', '')
    full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path.lstrip('/'))
    
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        abort(404)
    
    try:
        with Image.open(full_path) as img:
            img.thumbnail((100, 100))
            img_io = BytesIO()
            img.save(img_io, 'JPEG')
            img_io.seek(0)
            return send_file(img_io, mimetype='image/jpeg')
    except Exception as e:
        print(f"Error generating thumbnail: {str(e)}")
        abort(500)

@bp.route('/admin/media/download')
@login_required
@admin_required
def media_download():
    path = request.args.get('path', '')
    full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path.lstrip('/'))
    
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        abort(404)
    
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=True)

@bp.route('/admin/media/delete', methods=['POST'])
@login_required
@admin_required
def media_delete():
    data = request.json
    path = data.get('path', '')
    full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path.lstrip('/'))    
    if not os.path.exists(full_path):
        return jsonify({'success': False, 'message': 'File or folder not found'}), 404
    
    try:
        if os.path.isdir(full_path):
            os.rmdir(full_path)
        else:
            os.remove(full_path)
        return jsonify({'success': True, 'message': 'Item deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@bp.route('/admin/media/create_folder', methods=['POST'])
@login_required
@admin_required
def media_create_folder():
    data = request.json
    path = data.get('path', '/')
    name = data.get('name', '')
    
    if not name:
        return jsonify({'success': False, 'message': 'Folder name is required'}), 400
    
    full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path.lstrip('/'), name)
    
    if os.path.exists(full_path):
        return jsonify({'success': False, 'message': 'Folder already exists'}), 400
    
    try:
        os.makedirs(full_path)
        return jsonify({'success': True, 'message': 'Folder created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


































@bp.route('/ctf')
def ctf_home():
    return render_template('site/ctf.html')


@bp.route('/ctf/leaderboard')
def leaderboard():
    # Fetch user scores from the database
    print("Fetching user scores from the database...")
    users = User.query.all()
    
    # Prepare user data for the template
    user_data = []
    for user in users:
        total_score = user.calculate_total_score()
        user_data.append({
            'id': user.id,
            'name': user.name,
            'score_total': total_score,
            'avatarpath': user.avatarpath
        })
    
    # Sort users by total score
    user_data.sort(key=lambda x: x['score_total'], reverse=True)
    
    # Debug print to verify fetched data
    if user_data:
        print(f"Users: {user_data}")

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
        
        # Check if the user has already completed or used a hint for this challenge
        if current_user.is_authenticated:
            challenge_obtained = ChallengesObtained.query.filter_by(
                user_id=current_user.id, 
                challenge_id=challenge.id
            ).first()
            if challenge_obtained:
                challenge.completed = challenge_obtained.completed
                challenge.hint_used = challenge_obtained.used_hint
                challenge.completed_at = challenge_obtained.completed_at
            else:
                challenge.completed = False
                challenge.hint_used = False
                challenge.completed_at = None
        else:
            challenge.completed = False
            challenge.hint_used = False
            challenge.completed_at = None

    form = ChallengeSubmissionForm()
    return render_template('site/challenges.html', challenges=challenges, form=form)

@bp.route('/get_hint/<int:challenge_id>', methods=['POST'])
@login_required
def get_hint(challenge_id):
    try:
        challenge = Challenge.query.get_or_404(challenge_id)
        user_challenge = ChallengesObtained.query.filter_by(user_id=current_user.id, challenge_id=challenge_id).first()
        
        if not user_challenge:
            user_challenge = ChallengesObtained(user_id=current_user.id, challenge_id=challenge_id, used_hint=True)
            db.session.add(user_challenge)
        elif not user_challenge.used_hint:
            user_challenge.used_hint = True
        
        db.session.commit()
        
        
        
        print(f"Hint provided for challenge {challenge_id} to user {current_user.id}")
        return jsonify({
            'success': True,
            'hint': challenge.hint,
            'cost': challenge.hint_cost,
            
        })
    except Exception as e:
        db.session.rollback()
        print(f"Error getting hint for challenge {challenge_id}: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': 'An error occurred while fetching the hint.'
        }), 500



@bp.route('/admin/lab_editor/<int:lab_id>', methods=['GET', 'POST'])
@bp.route('/admin/lab_editor', methods=['GET', 'POST'])
@login_required
@admin_required
def lab_editor(lab_id=None):
    form = LabForm()
    lab = Lab.query.get(lab_id) if lab_id else None

    if request.method == 'GET':
        if lab:
            form = LabForm(obj=lab)
        return render_template('admin/lab_editor.html', form=form, lab=lab)

    if request.method == 'POST':
        data = request.get_json()
        print(f"Received JSON data: {data}")
        
        form = LabForm(data=data)
        if form.validate():
            try:
                if lab:
                    form.populate_obj(lab)
                    print(f"Updating existing lab: {lab.id}")
                else:
                    lab = Lab(
                        name=form.name.data,
                        image=form.image.data,
                        description=form.description.data,
                        vpn_server=form.vpn_server.data,
                        vpn_file=form.vpn_file.data,
                        date_created=datetime.utcnow()
                    )
                    db.session.add(lab)
                    print("Creating new lab")
                
                # Update the image field with the selected filename
                if form.image.data:
                    lab.image = form.image.data

                db.session.commit()
                print(f"Lab saved successfully: {lab.id}")
                return jsonify({'success': True, 'message': 'Lab saved successfully.', 'lab_id': lab.id})
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error saving lab: {str(e)}")
                return jsonify({'success': False, 'message': 'An error occurred while saving the lab.', 'error': str(e)}), 500
        else:
            print(f"Form validation errors: {form.errors}")
            return jsonify({'success': False, 'message': 'Form validation failed.', 'errors': form.errors}), 400

@bp.route('/admin/lab_manager', methods=['GET'])
@login_required
@admin_required
def lab_manager():
    print("Entered lab_manager route")
    labs = Lab.query.options(joinedload(Lab.hosts).joinedload(Host.flags)).all()
    csrf_form = CsrfProtectForm()
    
    labs_without_flags = []
    for lab in labs:
        if not any(host.flags for host in lab.hosts):
            labs_without_flags.append(lab)
    
    return render_template('admin/lab_manager.html', labs=labs, form=csrf_form, labs_without_flags=labs_without_flags)

@bp.route('/admin/delete_lab/<int:lab_id>', methods=['POST'])
@login_required
@admin_required
def delete_lab(lab_id):
    try:
        lab = Lab.query.get(lab_id)
        if lab:
            print(f"Deleting lab: {lab.name}")
            try:
                # Delete associated hosts first
                hosts_deleted = Host.query.filter_by(lab_id=lab_id).delete()
                db.session.delete(lab)
                db.session.commit()
                print(f"Lab and {hosts_deleted} associated hosts deleted successfully")
                return jsonify({'success': True, 'message': f'Lab and {hosts_deleted} associated hosts deleted successfully'})
            except Exception as e:
                db.session.rollback()
                print(f"Error deleting lab: {str(e)}", exc_info=True)
                return jsonify({
                    'success': False,
                    'message': f'An error occurred while deleting the lab: {str(e)}'
                }), 500
        else:
            print(f"Lab not found: {lab_id}")
            return jsonify({
                'success': False,
                'message': 'Lab not found'
            }), 404
    except Exception as e:
        print(f"Unexpected error in delete_lab: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'message': f'An unexpected error occurred: {str(e)}'
        }), 500

@bp.route('/admin/get_lab/<int:lab_id>', methods=['GET'])
@login_required
@admin_required
def get_lab(lab_id):
    lab = Lab.query.get_or_404(lab_id)
    return jsonify({
        'name': lab.name,
        'image': lab.image,
        'description': lab.description,
        'vpn_server': lab.vpn_server,
        'vpn_file': lab.vpn_file
    })

@bp.route('/admin/challenge_manager', methods=['GET'])
@login_required
@admin_required
def challenge_manager():
    print("Entered challenge_manager route")
    challenges = Challenge.query.all()
    csrf_form = CsrfProtectForm()
    return render_template('admin/challenge_manager.html', challenges=challenges, form=csrf_form)

@bp.route('/admin/delete_challenge/<int:challenge_id>', methods=['POST'])
@login_required
@admin_required
def delete_challenge(challenge_id):
    challenge = Challenge.query.get(challenge_id)
    if challenge:
        try:
            # Check for related data
            related_data = ChallengesObtained.query.filter_by(challenge_id=challenge_id).first()
            if related_data:
                return jsonify({
                    'success': False,
                    'message': 'Cannot delete challenge. It has related user progress data.'
                }), 400

            db.session.delete(challenge)
            db.session.commit()
            flash('Challenge deleted successfully.', 'success')
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error deleting challenge: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'An error occurred while deleting the challenge.'
            }), 500
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
                challenge.downloadable_file = form.downloadable_file.data
                challenge.hint = form.hint.data
                challenge.hint_cost = form.hint_cost.data
            else:
                challenge = Challenge(
                    name=form.name.data,
                    description=form.description.data,
                    flag_uuid=form.flag_uuid.data or str(uuid4()),
                    html_link=form.html_link.data,
                    point_value=form.point_value.data,
                    downloadable_file=form.downloadable_file.data,
                    hint=form.hint.data,
                    hint_cost=form.hint_cost.data
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
        form.downloadable_file.data = challenge.downloadable_file
        form.hint.data = challenge.hint
        form.hint_cost.data = challenge.hint_cost

    return render_template('admin/challenge_editor.html', form=form, challenge=challenge)


@bp.route('/ctf/quizzes')
@login_required
def quizzes():
    quizzes = Quiz.query.all()
    user_progress = UserQuizProgress.query.filter_by(user_id=current_user.id).all()
    completed_quizzes = {progress.quiz_id: progress.score for progress in user_progress if progress.completed}
    
    for quiz in quizzes:
        if quiz.image:
            quiz.image_url = url_for('static', filename=f'library/images/quizes/{quiz.image}')
        else:
            quiz.image_url = url_for('static', filename='library/images/quizes/default_quiz_image.jpg')
        
        # Calculate quiz details
        quiz_details = get_quiz_details(quiz.id)
        quiz.question_count = quiz_details['question_count']
        quiz.max_score = quiz_details['max_score']
    
    return render_template('site/quizzes.html', quizzes=quizzes, completed_quizzes=completed_quizzes)

@bp.route('/api/quiz_details/<int:quiz_id>')
@login_required
def get_quiz_details(quiz_id):
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    question_count = len(questions)
    max_score = sum(question.points for question in questions)
    return {'question_count': question_count, 'max_score': max_score}


@bp.route('/ctf/take_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    user_progress = UserQuizProgress.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first()

    if user_progress and user_progress.completed:
        flash('You have already completed this quiz.', 'info')
        return redirect(url_for('main.quiz_results', quiz_id=quiz_id))

    if not user_progress:
        user_progress = UserQuizProgress(user_id=current_user.id, quiz_id=quiz_id)
        db.session.add(user_progress)
        db.session.commit()

    questions = Question.query.filter_by(quiz_id=quiz_id).order_by(Question.id).all()
    
    if not questions:
        flash('This quiz has no questions.', 'warning')
        return redirect(url_for('main.quizzes'))

    if user_progress.current_question >= len(questions):
        user_progress.completed = True
        user_progress.completed_at = datetime.utcnow()
        db.session.commit()
        flash(f'Quiz completed! Your score: {user_progress.score}', 'success')
        return redirect(url_for('main.quiz_results', quiz_id=quiz_id))

    current_question = questions[user_progress.current_question]

    if request.method == 'POST':
        answer = request.form.get('answer')
        if not answer:
            flash('Please select an answer.', 'warning')
            return redirect(url_for('main.take_quiz', quiz_id=quiz_id))

        question_progress = UserQuestionProgress.query.filter_by(
            user_quiz_progress_id=user_progress.id,
            question_id=current_question.id
        ).first()

        if not question_progress:
            question_progress = UserQuestionProgress(
                user_quiz_progress_id=user_progress.id,
                question_id=current_question.id
            )
            db.session.add(question_progress)

        question_progress.answered = True
        question_progress.correct = (answer == current_question.correct_answer)
        question_progress.user_answer = answer

        if question_progress.correct:
            user_progress.score += current_question.points

        user_progress.current_question += 1
        db.session.commit()

        if user_progress.current_question >= len(questions):
            user_progress.completed = True
            user_progress.completed_at = datetime.utcnow()
            db.session.commit()
            flash(f'Quiz completed! Your score: {user_progress.score}', 'success')
            return redirect(url_for('main.quiz_results', quiz_id=quiz_id))
        
        if quiz.sequential:
            return redirect(url_for('main.take_quiz', quiz_id=quiz_id))
        else:
            flash('Answer recorded. You can continue with the next question or review previous ones.', 'info')

    return render_template('site/take_quiz.html', quiz=quiz, question=current_question, progress=user_progress)

@bp.route('/ctf/quiz_results/<int:quiz_id>')
@login_required
def quiz_results(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    user_progress = UserQuizProgress.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first_or_404()
    
    # Ensure all questions are marked as answered
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    for question in questions:
        question_progress = UserQuestionProgress.query.filter_by(
            user_quiz_progress_id=user_progress.id,
            question_id=question.id
        ).first()
        if not question_progress:
            question_progress = UserQuestionProgress(
                user_quiz_progress_id=user_progress.id,
                question_id=question.id,
                answered=False,
                correct=False
            )
            db.session.add(question_progress)
    
    db.session.commit()
    
    return render_template('site/quiz_results.html', quiz=quiz, user_progress=user_progress)

@bp.route('/submit_flag', methods=['POST'])
@login_required
def submit_flag():
    data = request.json
    host_id = data.get('host_id')
    flag_type = data.get('flag_type')
    submitted_flag = data.get('flag')

    if not all([host_id, flag_type, submitted_flag]):
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400

    try:
        flag = Flag.query.filter_by(host_id=host_id, type=flag_type).first()
        if not flag:
            return jsonify({'success': False, 'message': 'Invalid flag submission'}), 400

        if flag.uuid == submitted_flag:
            # Check if the user has already obtained this flag
            existing_flag = FlagsObtained.query.filter_by(user_id=current_user.id, flag_id=flag.id).first()
            if existing_flag:
                return jsonify({'success': False, 'message': 'You have already obtained this flag'}), 400

            # Create a new FlagsObtained record
            new_flag_obtained = FlagsObtained(user_id=current_user.id, flag_id=flag.id)
            db.session.add(new_flag_obtained)

            # Update user's score (redundant now)
            current_user.score_total += flag.point_value
            db.session.commit()

            return jsonify({'success': True, 'message': 'Flag submitted successfully!', 'new_score': current_user.score_total}), 200
        else:
            return jsonify({'success': False, 'message': 'Incorrect flag'}), 400

    except Exception as e:
        db.session.rollback()
        print(f"Error submitting flag: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while submitting the flag'}), 500

@bp.route('/submit_challenge_flag', methods=['POST'])
@login_required
def submit_challenge_flag():
    data = request.json
    challenge_id = data.get('challenge_id')
    submitted_flag = data.get('flag')

    if not all([challenge_id, submitted_flag]):
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400

    try:
        challenge = Challenge.query.get(challenge_id)
        if not challenge:
            return jsonify({'success': False, 'message': 'Invalid challenge'}), 400

        if challenge.flag_uuid == submitted_flag:
            # Check if the user has already completed this challenge
            existing_challenge = ChallengesObtained.query.filter_by(user_id=current_user.id, challenge_id=challenge.id).first()
            if existing_challenge:
                if existing_challenge.completed:
                    return jsonify({'success': False, 'message': 'You have already completed this challenge'}), 400
            else:
                existing_challenge = ChallengesObtained(user_id=current_user.id, challenge_id=challenge.id)
                db.session.add(existing_challenge)

            # Mark the challenge as completed
            existing_challenge.completed = True
            existing_challenge.completed_at = datetime.utcnow()

            db.session.commit()

            # Calculate the new total score
            new_score = current_user.calculate_total_score()

            return jsonify({
                'success': True, 
                'message': 'Challenge completed successfully!', 
                'new_score': new_score,
                'points_earned': challenge.point_value
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Incorrect flag'}), 400

    except Exception as e:
        db.session.rollback()
        print(f"Error submitting challenge flag: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while submitting the flag'}), 500

@bp.route('/ctf/hacking_labs')
@login_required
def hacking_labs():
    # Fetch labs and their hosts from the database, excluding flags
    labs = Lab.query.options(joinedload(Lab.hosts)).all()
    
    # Check if the user is an admin (we'll keep this for other potential admin features)
    is_admin = current_user.role == 'admin'

    # Initialize flags
    no_labs = len(labs) == 0
    labs_without_hosts = []

    for lab in labs:
        if len(lab.hosts) == 0:
            labs_without_hosts.append(lab)
        else:
            # Fetch the latest status for each host
            for host in lab.hosts:
                host.status = Host.query.get(host.id).status

    # Instantiate the FlagSubmissionForm
    form = FlagSubmissionForm()

    return render_template('site/hacking_labs.html', 
                           labs=labs, 
                           is_admin=is_admin, 
                           form=form, 
                           no_labs=no_labs, 
                           labs_without_hosts=labs_without_hosts)

@bp.route('/ctf/user_progress')
@login_required
def user_progress():
    # Fetch completed challenges with hint usage information
    completed_challenges = db.session.query(ChallengesObtained, Challenge).join(Challenge).filter(ChallengesObtained.user_id == current_user.id).all()
    
    # Fetch obtained flags
    obtained_flags = FlagsObtained.query.filter_by(user_id=current_user.id).all()
    
    # Fetch quiz progress
    quiz_progress = UserQuizProgress.query.filter_by(user_id=current_user.id).all()
    
    # Calculate total score using the new method
    total_score = current_user.calculate_total_score()
    
    # Fetch quiz results
    quiz_results = []
    for progress in quiz_progress:
        quiz = Quiz.query.get(progress.quiz_id)
        quiz_results.append({
            'title': quiz.title,
            'score': progress.score,
            'total_points': sum(question.points for question in quiz.questions),
            'completed': progress.completed,
            'passed': progress.score >= quiz.min_score,
            'min_score': quiz.min_score,
            'completed_at': progress.completed_at.strftime('%Y-%m-%d %H:%M:%S') if progress.completed_at else 'Not completed'
        })
    
    return render_template('site/user_progress.html', 
                           completed_challenges=completed_challenges,
                           obtained_flags=obtained_flags,
                           quiz_progress=quiz_progress,
                           quiz_results=quiz_results,
                           total_score=total_score)

@bp.route('/ctf/user_details/<int:user_id>')
@login_required
def user_details(user_id):
    user = User.query.get_or_404(user_id)
    
    # Fetch completed challenges with hint usage information
    completed_challenges = db.session.query(ChallengesObtained, Challenge).join(Challenge).filter(
        ChallengesObtained.user_id == user.id,
        ChallengesObtained.completed == True
    ).all()
    
    # Fetch obtained flags
    obtained_flags = FlagsObtained.query.filter_by(user_id=user.id).all()
    
    # Fetch quiz progress
    quiz_progress = UserQuizProgress.query.filter_by(user_id=user.id).all()
    
    # Calculate total score using the new method
    total_score = user.calculate_total_score()
    
    # Prepare user data
    user_data = {
        'id': user.id,
        'name': user.name,
        'avatarpath': user.avatarpath,
        'score_total': total_score
    }
    
    # Fetch quiz results
    quiz_results = []
    for progress in quiz_progress:
        quiz = Quiz.query.get(progress.quiz_id)
        quiz_results.append({
            'title': quiz.title,
            'score': progress.score,
            'total_points': sum(question.points for question in quiz.questions),
            'completed': progress.completed,
            'completed_at': progress.completed_at
        })
    
    return render_template('site/user_details.html', 
                           user_data=user_data,
                           user=user,
                           completed_challenges=completed_challenges,
                           obtained_flags=obtained_flags,
                           quiz_results=quiz_results,
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
                
                # Update the image_url field with the selected filename
                if form.image_url.data:
                    host.image_url = form.image_url.data

                print(f"Lab ID being set: {host.lab_id}")
                print(f"Full form data: {form.data}")
                db.session.commit()
                return jsonify({'success': True, 'message': 'Host saved successfully.'})
            except Exception as e:
                db.session.rollback()
                print(f"Error saving host: {str(e)}")
                return jsonify({'success': False, 'message': 'An error occurred while saving the host.', 'errors': form.errors}), 400
        else:
            print(f"Form validation failed: {form.errors}")
            return jsonify({'success': False, 'message': 'Validation failed.', 'errors': form.errors}), 400

    if host:
        form = HostForm(obj=host)
        form.lab_id.data = host.lab_id
    else:
        form.lab_id.data = labs[0].id if labs else None  # Set a default lab if available
    
    # Populate the image choices
    form.image_url.choices = [('', 'Select an image')] + [(f, f) for f in get_image_choices()]
    
    return render_template('admin/host_editor.html', form=form, host=host, labs=labs)

def get_image_choices():
    image_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'hosts')
    image_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
    return image_files

@bp.route('/ctf/host_details/<int:host_id>')
@login_required
def host_details(host_id):
    print(f"Accessing host details for host_id: {host_id}")
    auth_status = check_azure_authentication()

    host = Host.query.get_or_404(host_id)
    vm_status = None
    if host.azure_vm_id:
        print(f"Azure VM ID associated with this host: {host.azure_vm_id}")
    else:
        print("No Azure VM ID associated with this host")
    return render_template('site/host_details.html', host=host, vm_status=vm_status, auth_status=auth_status)



@bp.route('/admin/delete_host/<int:host_id>', methods=['POST'])
@login_required
@admin_required
def delete_host(host_id):
    host = Host.query.get(host_id)
    if host:
        try:
            db.session.delete(host)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            print(f"Error deleting host: {str(e)}")
            return jsonify({'success': False, 'message': 'An error occurred while deleting the host.'}), 500
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
    for quiz in quizzes:
        if quiz.image:
            quiz.image_path = url_for('static', filename=f'library/images/quizes/{quiz.image}')
        else:
            quiz.image_path = url_for('static', filename='library/images/quizes/default_quiz_image.jpg')
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
            quiz.image = form.image.data
            quiz.sequential = form.sequential.data
        else:
            quiz = Quiz(title=form.title.data, description=form.description.data, min_score=form.min_score.data, image=form.image.data, sequential=form.sequential.data)
            db.session.add(quiz)
        db.session.commit()
        flash('Quiz saved successfully.', 'success')
        return redirect(url_for('main.quiz_manager'))

    if quiz:
        form.title.data = quiz.title
        form.description.data = quiz.description
        form.min_score.data = quiz.min_score
        form.image.data = quiz.image
        form.sequential.data = quiz.sequential

    return render_template('admin/quiz_editor.html', form=form, quiz=quiz)

@bp.route('/admin/help')
@login_required
@admin_required
def admin_help():
    return render_template('admin/admin_help.html')

@bp.route('/admin/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get(quiz_id)
    if quiz:
        # Check for related questions
        if quiz.questions:
            flash('Cannot delete quiz. Please delete all questions first.', 'error')
            return redirect(url_for('main.quiz_manager'))
        
        # Check for user progress records
        user_progress = UserQuizProgress.query.filter_by(quiz_id=quiz_id).first()
        if user_progress:
            flash('Cannot delete quiz. There are user progress records associated with this quiz.', 'error')
            return redirect(url_for('main.quiz_manager'))
        
        try:
            db.session.delete(quiz)
            db.session.commit()
            flash('Quiz deleted successfully.', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error deleting quiz: {str(e)}")
            flash('An error occurred while deleting the quiz.', 'error')
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
            # Check if there's any user progress for this question
            user_progress_exists = UserQuestionProgress.query.filter_by(question_id=question_id).first() is not None
            if user_progress_exists:
                flash('Warning: Editing this question will affect existing user progress.', 'warning')
            
            question.question_text = form.question_text.data
            question.option_a = form.option_a.data
            question.option_b = form.option_b.data
            question.option_c = form.option_c.data
            question.option_d = form.option_d.data
            question.correct_answer = form.correct_answer.data
            question.points = form.points.data
            question.image = form.image.data
            question.explanation = form.explanation.data
        else:
            question = Question(
                quiz_id=quiz_id,
                question_text=form.question_text.data,
                option_a=form.option_a.data,
                option_b=form.option_b.data,
                option_c=form.option_c.data,
                option_d=form.option_d.data,
                correct_answer=form.correct_answer.data,
                points=form.points.data,
                image=form.image.data,
                explanation=form.explanation.data
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
        form.image.data = question.image
        form.explanation.data = question.explanation




        # Check if there's any user progress for this question
        user_progress_exists = UserQuestionProgress.query.filter_by(question_id=question_id).first() is not None
        if user_progress_exists:
            flash('Warning: Editing or deleting this question will affect existing user progress.', 'warning')

    return render_template('admin/question_editor.html', form=form, quiz=quiz, question=question)

@bp.route('/admin/delete_question/<int:question_id>', methods=['POST'])
@login_required
@admin_required
def delete_question(question_id):
    question = Question.query.get(question_id)
    if question:
        quiz_id = question.quiz_id
        
        # Delete related UserQuestionProgress entries
        UserQuestionProgress.query.filter_by(question_id=question_id).delete()
        
        # Update UserQuizProgress scores
        user_quiz_progresses = UserQuizProgress.query.filter_by(quiz_id=quiz_id).all()
        for progress in user_quiz_progresses:
            if progress.score >= question.points:
                progress.score -= question.points
        
        db.session.delete(question)
        db.session.commit()
        flash('Question and related progress data deleted successfully.', 'success')
        return redirect(url_for('main.quiz_editor', quiz_id=quiz_id))
    else:
        flash('Question not found.', 'error')
        return redirect(url_for('main.quiz_manager'))
    
    
@bp.route('/manage_vm', methods=['POST'])
@login_required
def manage_vm():
    print(f"Received request to manage VM: {request.form}")
    resource_group = request.form['resource_group']
    vm_name = request.form['vm_name']
    action = request.form['action']
    subscription_id = Config.AZURE_SUBSCRIPTION_ID
    vm_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
    az_cli_path = get_azure_cli_path()
    try:
        output = ""
        if action == 'status':
            print(f"Executing VM status command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'get-instance-view', '--ids', vm_id, '--query', '{name:name, powerState:instanceView.statuses[1].displayStatus, osType:storageProfile.osDisk.osType}'], capture_output=True, text=True)
            if result.returncode == 0:
                vm_info = json.loads(result.stdout)
                output = f"VM Name: {vm_info['name']}, Power State: {vm_info['powerState']}, OS Type: {vm_info['osType']}"
                
                # Update the database with the VM status
                host = Host.query.filter_by(azure_vm_id=vm_id).first()
                if host:
                    host.status = vm_info['powerState'].lower() == 'vm running'
                    db.session.commit()
            else:
                raise Exception(f"Error fetching VM status: {result.stderr}")
        elif action == 'start':
            print(f"Executing VM start command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'start', '--ids', vm_id], capture_output=True, text=True)
            if result.returncode == 0:
                host = Host.query.filter_by(azure_vm_id=vm_id).first()
                if host:
                    host.status = True
                    db.session.commit()
        elif action == 'stop':
            print(f"Executing VM stop command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'stop', '--ids', vm_id], capture_output=True, text=True)
            if result.returncode == 0:
                host = Host.query.filter_by(azure_vm_id=vm_id).first()
                if host:
                    host.status = False
                    db.session.commit()
        else:
            print(f"Invalid action received: {action}")
            raise ValueError("Invalid action")
        
        if result.returncode != 0:
            if action == 'status':
                raise Exception(f"Error fetching VM status: {result.stderr}")
            else:
                raise Exception(f"Error performing {action} on VM: {result.stderr}")
        
        if not output:
            output = f"Successfully performed {action} on VM: {vm_id}"
        print(output)
        return jsonify({"status": "success", "message": output})
    except Exception as e:
        print(f"Detailed error while managing VM: {e}")
        print(f"Error managing VM: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400

@bp.route('/update_host_status', methods=['POST'])
@login_required
def update_host_status():
    host_id = request.form.get('host_id')
    status = request.form.get('status') == 'true'
    host = Host.query.get(host_id)
    if host:
        host.status = status
        db.session.commit()
        return jsonify({"status": "success", "message": "Host status updated successfully"})
    return jsonify({"status": "error", "message": "Host not found"}), 404

@bp.route('/manage_vpn', methods=['POST'])
@login_required
def manage_vpn():
    print(f"Received request to manage VPN: {request.json}")
    action = request.json['action']
    lab_id = request.json['lab_id']
    lab = Lab.query.get_or_404(lab_id)
    vpn_server_name = lab.vpn_server  # Use the lab's vpn_server field
    subscription_id = Config.AZURE_SUBSCRIPTION_ID
    resource_group = Config.AZURE_RESOURCE_GROUP
    vm_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vpn_server_name}"
    az_cli_path = get_azure_cli_path()
    
    try:
        output = ""
        if action == 'status':
            print(f"Executing VPN status command for{vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'get-instance-view', '--ids', vm_id, '--query', '{name:name, powerState:instanceView.statuses[1].displayStatus}'], capture_output=True, text=True)
            if result.returncode == 0:
                vm_info = json.loads(result.stdout)
                output = f"VPN Server: {vm_info['name']}, Power State: {vm_info['powerState']}"
            else:
                raise Exception(f"Error fetching VPN status: {result.stderr}")
        elif action == 'start':
            print(f"Executing VPN start command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'start', '--ids', vm_id], capture_output=True, text=True)
            if result.returncode == 0:
                output = "VPN server started successfully"
            else:
                raise Exception(f"Error starting VPN: {result.stderr}")
        elif action == 'stop':
            print(f"Executing VPN stop command for {vm_id}")
            result = subprocess.run([az_cli_path, 'vm', 'stop', '--ids', vm_id], capture_output=True, text=True)
            if result.returncode == 0:
                output = "VPN server stopped successfully"
            else:
                raise Exception(f"Error stopping VPN: {result.stderr}")
        else:
            print(f"Invalid action received: {action}")
            raise ValueError("Invalid action")
        
        print(output)
        return jsonify({"status": "success", "message": output})
    except Exception as e:
        print(f"Detailed error while managing VPN: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400
    
    
@bp.route('/ctf/vpn_management/<int:lab_id>')
@login_required
def vpn_management(lab_id):
    lab = Lab.query.get_or_404(lab_id)
    vpn_server_name = lab.vpn_server  # Use the lab's vpn_server field
    
    return render_template('site/vpn_management.html', lab=lab, vpn_server_name=vpn_server_name)

@bp.route('/admin/flag_manager')
@login_required
@admin_required
def flag_manager():
    flags = Flag.query.all()
    return render_template('admin/flag_manager.html', flags=flags)

@bp.route('/admin/edit_flag/<int:flag_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_flag(flag_id):
    flag = Flag.query.get_or_404(flag_id)
    form = FlagForm(obj=flag)
    
    if request.method == 'GET':
        form.host_id.data = flag.host_id
    
    if form.validate_on_submit():
        form.populate_obj(flag)
        db.session.commit()
        flash('Flag updated successfully', 'success')
        return redirect(url_for('main.flag_manager'))
    
    return render_template('admin/flag_editor.html', form=form, flag=flag)

@bp.route('/admin/delete_flag/<int:flag_id>', methods=['POST'])
@login_required
@admin_required
def delete_flag(flag_id):
    flag = Flag.query.get_or_404(flag_id)
    try:
        db.session.delete(flag)
        db.session.commit()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Flag deleted successfully'})
        else:
            flash('Flag deleted successfully', 'success')
            return redirect(url_for('main.flag_manager'))
    except Exception as e:
        db.session.rollback()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': str(e)}), 500
        else:
            flash(f'Error deleting flag: {str(e)}', 'error')
            return redirect(url_for('main.flag_manager'))

@bp.route('/admin/add_flag', methods=['GET', 'POST'])
@login_required
@admin_required
def add_flag():
    form = FlagForm()
    if form.validate_on_submit():
        new_flag = Flag(
            type=form.type.data,
            uuid=form.uuid.data,
            point_value=form.point_value.data,
            host_id=form.host_id.data
        )
        db.session.add(new_flag)
        db.session.commit()
        flash('New flag added successfully', 'success')
        return redirect(url_for('main.flag_manager'))
    return render_template('admin/flag_editor.html', form=form)


@bp.route('/admin/studyroom_manager')
@login_required
@admin_required
def studyroom_manager():
    courses = Course.query.all()
    return render_template('admin/studyroom_manager.html', courses=courses)

@bp.route('/admin/course_editor', methods=['GET', 'POST'])
@bp.route('/admin/course_editor/<int:course_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def course_editor(course_id=None):
    form = CourseForm()
    course = Course.query.get(course_id) if course_id else None

    if form.validate_on_submit():
        if course:
            form.populate_obj(course)
        else:
            course = Course(
                name=form.name.data,
                description=form.description.data,
                file_attachment=form.file_attachment.data,
                image=form.image.data,
                tags=form.tags.data,
                purchase_url=form.purchase_url.data
            )
            db.session.add(course)
        db.session.commit()
        flash('Course saved successfully.', 'success')
        return redirect(url_for('main.studyroom_manager'))
    elif form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field.capitalize()}: {error}", 'error')

    if course:
        form = CourseForm(obj=course)

    return render_template('admin/course_editor.html', form=form, course=course)

@bp.route('/admin/delete_course/<int:course_id>', methods=['POST'])
@login_required
@admin_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    db.session.delete(course)
    db.session.commit()
    flash('Course deleted successfully.', 'success')
    return redirect(url_for('main.studyroom_manager'))


@bp.route('/ctf/study_room')
@login_required
def study_room():
    tag = request.args.get('tag')
    search = request.args.get('search')
    
    courses_query = Course.query
    
    if tag:
        courses_query = courses_query.filter(Course.tags.contains(tag))
    
    if search:
        courses_query = courses_query.filter(
            (Course.name.ilike(f'%{search}%')) | (Course.description.ilike(f'%{search}%'))
        )
    
    courses = courses_query.all()
    
    # Add purchase URL to each course
    for course in courses:
        course.purchase_url = course.purchase_url if course.purchase_url else None
    all_tags = set()
    for course in Course.query.all():
        if course.tags:
            all_tags.update(tag.strip() for tag in course.tags.split(','))
    
    return render_template('site/study_room.html', courses=courses, all_tags=all_tags, current_tag=tag, search=search)

@bp.route('/ctf/course_details/<int:course_id>')
@login_required
def course_details(course_id):
    course = Course.query.get_or_404(course_id)
    return render_template('site/course_details.html', course=course)

@bp.route('/ctf/view_course_material/<path:filename>')
@login_required
def view_course_material(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], 'studyfiles/' + filename)