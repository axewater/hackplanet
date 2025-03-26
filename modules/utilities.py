#/modules/utilities.py
import re, requests, shutil, os, zipfile, smtplib, socket
from functools import wraps
from flask import flash, redirect, url_for, request, current_app, flash
from flask_login import current_user, login_user
from flask_mail import Mail, Message
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
import logging, socket
from smtplib import SMTPException, SMTPAuthenticationError, SMTPConnectError, SMTPDataError, SMTPHeloError, SMTPRecipientsRefused, SMTPSenderRefused
from ssl import SSLError
from smtplib import SMTPException, SMTPAuthenticationError, SMTPConnectError, SMTPDataError, SMTPHeloError, SMTPRecipientsRefused, SMTPSenderRefused
from ssl import SSLError

def sanitize_log_data(data):
    """Sanitize sensitive information before logging."""
    if isinstance(data, str):
        return data.replace(current_app.config['MAIL_PASSWORD'], '********')
    return data

def is_server_reachable(server, port):
    """
    Check if the mail server is reachable.
    """
    try:
        # Attempt to open a connection to the mail server
        with socket.create_connection((server, port), timeout=5) as connection:
            logging.info(f"Successfully connected to {server}:{port}")
            return True
    except Exception as e:
        # Print or log the error if needed
        print(f"Error connecting to mail server: {e}")
        logging.error(f"Error connecting to mail server {server}:{port}: {e}")
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
    mail_use_auth = current_app.config['MAIL_USE_AUTH']

    logging.info(f"Attempting to send email to {to} with subject '{subject}'")

    # Check if mail server is reachable
    if not is_server_reachable(mail_server, mail_port):
        print(f"Mail server {mail_server}:{mail_port} is unreachable. Email not sent.")
        flash(f"Mail server {mail_server}:{mail_port} is unreachable. Email not sent.")
        logging.error(f"Mail server {mail_server}:{mail_port} is unreachable. Email not sent.")
        flash(f"Unable to connect to the mail server. Please try again later or contact support.", "error")
        return

    # Attempt to send email
    try:
        # Create email message using Flask-Mail
        msg = Message(
            subject,
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[to],
            html=template
        )

        # Send email using Flask-Mail
        mail.send(msg)

        print(f"Email sent to {to} with subject {subject}")
        flash(f"Email sent to {to} with subject {subject}")
        logging.info(f"Email sent successfully to {to}")
        flash(f"Email sent successfully to {to}", "success")
    except SMTPAuthenticationError:
        logging.error(f"SMTP Authentication failed for user {mail_username}", exc_info=True)
        flash("Failed to authenticate with the email server. Please check the server settings.", "error")
    except SMTPConnectError:
        logging.error(f"Failed to connect to the SMTP server {mail_server}:{mail_port}", exc_info=True)
        flash("Failed to connect to the email server. Please try again later.", "error")
    except SMTPDataError as e:
        logging.error(f"SMTP data error: {sanitize_log_data(str(e))}", exc_info=True)
        flash("An error occurred while sending the email. Please try again.", "error")
    except SMTPRecipientsRefused:
        logging.error(f"Recipient refused: {to}", exc_info=True)
        flash("The recipient's email address was refused. Please check the email address and try again.", "error")
    except SMTPSenderRefused:
        logging.error(f"Sender address refused: {current_app.config['MAIL_DEFAULT_SENDER']}", exc_info=True)
        flash("The sender's email address was refused. Please contact support.", "error")
    except SSLError:
        logging.error(f"SSL/TLS error occurred while connecting to {mail_server}:{mail_port}", exc_info=True)
        flash("A secure connection error occurred. Please try again or contact support.", "error")
    except Exception as e:
        # Handle specific errors if needed
        print(f"Error sending email: {e}")
        logging.error(f"Unexpected error while sending email: {sanitize_log_data(str(e))}", exc_info=True)
        flash("An unexpected error occurred while sending the email. Please try again or contact support.", "error")
def send_password_reset_email(user_email, token):
    """
    Send a password reset email to the user with a link to reset their password.
    """
    reset_url = url_for('main.reset_password', token=token, _external=True)

    # Create email message using Flask-Mail
    msg = Message(
        'Password Reset Request',
        sender=current_app.config['MAIL_DEFAULT_SENDER'], 
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

    try:
        # Send email using Flask-Mail
        mail.send(msg)
        logging.info(f"Password reset email sent to {user_email}")
        flash(f"Password reset email sent to {user_email}", "success")
    except Exception as e:
        logging.error(f"Error sending password reset email: {e}", exc_info=True)
        flash("An error occurred while sending the password reset email. Please try again later.", "error")
        
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
            next_page = url_for('bp_login.restricted')
        return redirect(next_page)
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('bp_login.login'))
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You must be an admin to access this page.", "danger")
            return redirect(url_for('bp_login.login'))
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