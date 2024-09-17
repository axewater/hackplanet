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


bp = Blueprint('main', __name__)



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