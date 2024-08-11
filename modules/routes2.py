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
    QuizForm, QuestionForm, FlagForm
)

from modules.models import (
    User, Whitelist, UserPreference, GlobalSettings, InviteToken, Lab, Challenge, Host, 
    Flag, UserProgress, FlagsObtained, ChallengesObtained, Quiz, Question, UserQuizProgress
)
from modules.utilities import (
    admin_required, _authenticate_and_redirect, square_image, send_email, send_password_reset_email, 
)
from modules.azure_utils import get_vm_status, check_azure_authentication


bp = Blueprint('main', __name__)


s = URLSafeTimedSerializer('YMecr3tK?IzzsSa@e!Zithpze') 
AZ_CLI_PATH = r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
has_initialized_whitelist = False
has_upgraded_admin = False
has_initialized_setup = False
app_start_time = datetime.now()
app_version = '1.2.1'



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
            current_app.logger.info(f"Deleting lab: {lab.name}")
            try:
                # Delete associated hosts first
                hosts_deleted = Host.query.filter_by(lab_id=lab_id).delete()
                db.session.delete(lab)
                db.session.commit()
                current_app.logger.info(f"Lab and {hosts_deleted} associated hosts deleted successfully")
                return jsonify({'success': True, 'message': f'Lab and {hosts_deleted} associated hosts deleted successfully'})
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error deleting lab: {str(e)}", exc_info=True)
                return jsonify({
                    'success': False,
                    'message': f'An error occurred while deleting the lab: {str(e)}'
                }), 500
        else:
            current_app.logger.warning(f"Lab not found: {lab_id}")
            return jsonify({
                'success': False,
                'message': 'Lab not found'
            }), 404
    except Exception as e:
        current_app.logger.error(f"Unexpected error in delete_lab: {str(e)}", exc_info=True)
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

                print(f"Debug: Lab ID being set: {host.lab_id}")
                print(f"Debug: Full form data: {form.data}")
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
        db.session.delete(host)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({
            'success': False,
            'message': 'Host not found'
        }), 404