#/modules/utilities.py
import re, requests, shutil, os, zipfile, smtplib, socket
from functools import wraps
from flask import flash, redirect, url_for, request, current_app, flash
from flask_login import current_user, login_user
from flask_mail import Message as MailMessage
from datetime import datetime
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from modules.models import (
    User, User, Whitelist
)
from modules import db, mail
from sqlalchemy import func, String
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError

from PIL import Image as PILImage
from PIL import ImageOps
from datetime import datetime
from wtforms.validators import ValidationError

def is_server_reachable(server, port):
    """
    Check if the mail server is reachable.
    """
    try:
        # Attempt to open a connection to the mail server
        with socket.create_connection((server, port), timeout=5) as connection:
            return True
    except Exception as e:
        # Print or log the error if needed
        print(f"Error connecting to mail server: {e}")
        return False
    
def send_email(to, subject, template):
    """
    Send an email with error handling and pre-send check.
    """
    # Mail server details from configuration
    mail_server = current_app.config['MAIL_SERVER']
    mail_port = current_app.config['MAIL_PORT']
    mail_username = current_app.config['MAIL_USERNAME']
    mail_password = current_app.config['MAIL_PASSWORD']
    mail_use_tls = current_app.config['MAIL_USE_TLS']

    # Check if mail server is reachable
    if not is_server_reachable(mail_server, mail_port):
        print(f"Mail server {mail_server}:{mail_port} is unreachable. Email not sent.")
        flash(f"Mail server {mail_server}:{mail_port} is unreachable. Email not sent.")
        return

    # Attempt to send email
    try:
        # Send email
        msg = MailMessage(
            subject,
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[to],
            html=template
        )
        mail.send(msg)
        print(f"Email sent to {to} with subject {subject}")
        flash(f"Email sent to {to} with subject {subject}")
    except Exception as e:
        # Handle specific errors if needed
        print(f"Error sending email: {e}")

def send_password_reset_email(user_email, token):
    reset_url = url_for('main.reset_password', token=token, _external=True)
    msg = MailMessage(
        'Password Reset Request',
        sender='noreply@ctfplatform.com', 
        recipients=[user_email]
    )
    msg.body = '''Hello,

You have requested to reset your password. If you did not make this request, please ignore this email. For security reasons, please ensure your email client supports HTML messages.

Best regards,

HackPlanet.EU Team
'''
    msg.html = f'''<p>Hello,</p>

<p>You have requested to reset your password. Click on the link below to set a new password:</p>

<p><a href="{reset_url}">Password Reset Link</a></p>

<p>If you did not request this, please ignore this email and your password will remain unchanged.</p>

<p>Best regards,</p>

<p>HackPlanet.EU Team</p>

<p>P.S. If you encounter any issues, feel free to contact us at <a href="mailto:support@HackPlanet.EU">support@ctfplatform.com</a>, and we will assist you in regaining access to your account!</p>
'''
    mail.send(msg)




def _authenticate_and_redirect(username, password):
    user = User.query.filter(func.lower(User.name) == func.lower(username)).first()
    
    if user and user.check_password(password):
        # If the password is correct and is using bcrypt, rehash it with Argon2
        if not user.password_hash.startswith('$argon2'):
            user.rehash_password(password)
            db.session.commit()

        user.lastlogin = datetime.utcnow()
        db.session.commit()
        login_user(user, remember=True)
        
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.restricted')
        return redirect(next_page)
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('main.login'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You must be an admin to access this page.", "danger")
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function


def escape_special_characters(pattern):
    """Escape special characters in the pattern to prevent regex errors."""
    if not isinstance(pattern, str):
        pattern = str(pattern)  # Convert to string if not already
    return re.escape(pattern)

def square_image(image, size):
    image.thumbnail((size, size))
    if image.size[0] != size or image.size[1] != size:
        new_image = PILImage.new('RGB', (size, size), color='black')
        offset = ((size - image.size[0]) // 2, (size - image.size[1]) // 2)
        new_image.paste(image, offset)
        image = new_image
    return image

