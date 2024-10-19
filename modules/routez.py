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
    QuizForm, QuestionForm, FlagForm, CourseForm, ThemeUploadForm, UserThemePreferencesForm
)

from modules.models import (
    User, Whitelist, UserPreference, GlobalSettings, InviteToken, Lab, Challenge, Host,
    Flag, UserProgress, FlagsObtained, ChallengesObtained, Quiz, Question, UserQuizProgress, UserQuestionProgress, Course
)
from modules.utilities import (
    admin_required, _authenticate_and_redirect, square_image, send_email, send_password_reset_email, 
)
from modules.azure_utils import check_azure_authentication, get_azure_cli_path
from modules.theme_manager import ThemeManager
import logging

bp = Blueprint('main', __name__)

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
        if action == 'start':
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
                db.session.commit()
        else:
            print(f"Invalid action received: {action}")
            raise ValueError("Invalid action")
        if result.returncode != 0:
            raise Exception(f"Error performing {action} on VM: {result.stderr}")
        if not output:
            output = f"Successfully performed {action} on VM: {vm_id}"
        print(output)
        return jsonify({"status": "success", "message": output})
    except Exception as e:
        print(f"Detailed error while managing VM: {e}")
        print(f"Error managing VM: {e}")
        return jsonify({"status": "error", "message": str(e)}), 400


@bp.route('/manage_vpn', methods=['POST'])
@login_required
def manage_vpn():
    print(f"Received request to manage VPN: {request.json}")
    action = request.json['action']
    lab_id = request.json['lab_id']
    lab = Lab.query.get_or_404(lab_id)
    vpn_server_name = lab.vpn_server  # Use the lab's vpn_server field
    if not vpn_server_name:
        return jsonify({"status": "error", "message": "No VPN server associated with this lab"}), 400
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
    
