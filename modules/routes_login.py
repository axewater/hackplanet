from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, current_app
from flask_login import current_user, login_required
from modules import db
from modules.models import User, InviteToken, Whitelist, SystemMessage, UserPreference
from modules.theme_manager import ThemeManager
from modules.forms import LoginForm, RegistrationForm, ResetPasswordRequestForm, InviteForm, CsrfProtectForm
from modules.utilities import send_email, send_password_reset_email, _authenticate_and_redirect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func
from datetime import datetime, timedelta, timezone
import logging, uuid
from uuid import uuid4
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

bp_login = Blueprint('bp_login', __name__)

@bp_login.context_processor
def utility_processor():
    def get_unread_message_count():
        if current_user.is_authenticated:
            return SystemMessage.query.filter(
                ~SystemMessage.read_by.contains(current_user)
            ).count()
        return 0
    return dict(get_unread_message_count=get_unread_message_count)

@bp_login.context_processor
def inject_current_theme():
    current_theme = 'default'
    if current_user.is_authenticated:
        if current_user.preferences:
            current_theme = current_user.preferences.theme or 'default'
        else:
            current_user.preferences = UserPreference(user_id=current_user.id)
            db.session.add(current_user.preferences)
            db.session.commit()
    theme_manager = ThemeManager(current_app)
    theme_data = theme_manager.get_theme_data(current_theme)
    return dict(current_theme=current_theme, theme_data=theme_data)

@bp_login.route('/restricted')
@login_required
def restricted():
    print("Route: /restricted")
    return render_template('site/restricted_area.html', title='Restricted Area')

@bp_login.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('bp_login.restricted'))

    print("Route: /login")
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(name=username).first()

        if user:
            if not user.is_email_verified:
                flash('Your account is not activated, check your email.', 'warning')
                return redirect(url_for('bp_login.login'))

            if not user.state:
                flash('Your account has been banned.', 'error')
                print(f"Error: Attempted login to disabled account - User: {username}")
                return redirect(url_for('bp_login.login'))

            return _authenticate_and_redirect(username, password)
        else:
            flash('Invalid username or password. USERNAMES ARE CASE SENSITIVE!', 'error')
            return redirect(url_for('bp_login.login'))

    return render_template('login/login.html', form=form)


@bp_login.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('bp_login.login'))
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
            return redirect(url_for('bp_login.register'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            email_address = form.email.data.lower()
            existing_user_email = User.query.filter(func.lower(User.email) == email_address).first()
            if existing_user_email:
                print(f"/register: Email already in use - {email_address}")
                flash('This email is already in use. Please use a different email or log in.')
                return redirect(url_for('bp_login.register'))
                    # Proceed with the whitelist check only if no valid invite token is provided
            if not invite:
                whitelist = Whitelist.query.filter(func.lower(Whitelist.email) == email_address).first()
                if not whitelist:
                    flash('Your email is not whitelisted.')
                    return redirect(url_for('bp_login.register'))

            existing_user = User.query.filter_by(name=form.username.data).first()
            if existing_user is not None:
                print(f"/register: User already exists - {form.username.data}")
                flash('User already exists. Please Log in.')
                return redirect(url_for('bp_login.register'))

            user_uuid = str(uuid4())
            existing_uuid = User.query.filter_by(user_id=user_uuid).first()
            if existing_uuid is not None:
                print("/register: UUID collision detected.")
                flash('An error occurred while registering. Please try again.')
                return redirect(url_for('bp_login.register'))

            user = User(
                user_id=user_uuid,
                name=form.username.data,
                email=form.email.data.lower(),  # Ensuring lowercase
                role='user',
                is_email_verified=False,
                email_verification_token=s.dumps(form.email.data, salt='email-confirm'),
                token_creation_time=datetime.utcnow(),
                created=datetime.utcnow(),
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


@bp_login.route('/confirm/<token>')
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


@bp_login.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('bp_login.login'))
    form = ResetPasswordRequestForm()
    
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            if user.token_creation_time and (datetime.utcnow() - user.token_creation_time).total_seconds() < 120:
                flash('Please wait a bit before requesting another password reset.')
                return redirect(url_for('bp_login.login'))
            password_reset_token = str(uuid.uuid4())
            user.password_reset_token = password_reset_token
            user.token_creation_time = datetime.utcnow()
            db.session.commit()
            send_password_reset_email(user.email, password_reset_token)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('bp_login.login'))

    return render_template('login/reset_password_request.html', form=form)

@bp_login.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('bp_login.login'))

    user = User.query.filter_by(password_reset_token=token).first()
    if not user or user.token_creation_time + timedelta(minutes=15) < datetime.utcnow():
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('bp_login.login'))

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
        return redirect(url_for('bp_login.login'))

    return render_template('login/reset_password.html', form=form, token=token)


@bp_login.route('/login/invites', methods=['GET', 'POST'])
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
                invite_url = url_for('bp_login.register', token=token, _external=True, _scheme='https')
                send_invite_email(email, invite_url)
                flash('Invite sent successfully and email added/updated in whitelist. The invite expires after 48 hours.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred: {str(e)}', 'error')
        else:
            flash('You have reached your invite limit.', 'danger')
        return redirect(url_for('bp_login.invites'))

    invites = InviteToken.query.filter_by(creator_user_id=current_user.user_id).all()
    current_invites_count = len([invite for invite in invites if not invite.used])
    remaining_invites = max(0, current_user.invite_quota - current_invites_count)

    return render_template('/login/invites.html', form=form, invites=invites, invite_quota=current_user.invite_quota, remaining_invites=remaining_invites, datetime=datetime)

@bp_login.route('/delete_invite/<int:invite_id>', methods=['POST'])
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