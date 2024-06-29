# modules/routes.py
import os, logging

from config import Config
from flask import Flask, render_template, flash, redirect, url_for, request, Blueprint, jsonify, session, abort, current_app, send_from_directory

from flask_login import current_user, login_required

from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy.orm import joinedload
from sqlalchemy import func, Integer, Text, case

from werkzeug.utils import secure_filename

from modules import db, mail, cache
from uuid import uuid4
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature


from modules.forms import (
    
    CsrfProtectForm, LabForm, FlagSubmissionForm
)

from modules.models import (
    User, Whitelist, UserPreference,GlobalSettings, Lab, Challenge, Host, Flag, UserProgress, FlagsObtained
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





@bp.route('/ctf')
def ctf_home():
    return render_template('site/ctf.html')


@bp.route('/ctf/leaderboard')
def leaderboard():
    # Fetch user scores from the database
    logging.info("Fetching user scores from the database...")
    users = User.query.with_entities(User.name, User.score_total, User.avatarpath).order_by(User.score_total.desc()).all()
    
    # Debug logging.info to verify fetched data
    if users:
        logging.info(f"Users: {users} avatarpath: {users[0].avatarpath}")

    return render_template('site/leaderboard.html', users=users)




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
        db.session.delete(lab)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({
            'success': False,
            'message': 'Lab not found'
        }), 404



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