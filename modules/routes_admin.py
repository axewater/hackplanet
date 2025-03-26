from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_file, send_from_directory, current_app
from flask_login import login_required
from modules import db, cache, mail
from modules.models import GlobalSettings, Whitelist, SystemMessage, User, Lab, Host, Challenge, ChallengesObtained, ProfileBackground
from modules.forms import NewsletterForm, WhitelistForm, SystemMessageForm, CsrfProtectForm, LabForm, ChallengeForm, HostForm
from sqlalchemy.orm import joinedload
from modules.utilities import admin_required
from modules.globals import app_start_time, app_version
from datetime import datetime
from flask import current_app, request, jsonify, send_file, abort, redirect, url_for, flash
from flask_login import current_user
import os, mimetypes, platform, socket
from PIL import Image
from io import BytesIO
from flask_mail import Message as MailMessage
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from config import Config
import logging

bp_admin = Blueprint('bp_admin', __name__)

@bp_admin.context_processor
def utility_processor():
    def get_unread_message_count():
        if current_user.is_authenticated:
            return SystemMessage.query.filter(
                ~SystemMessage.read_by.contains(current_user)
            ).count()
        return 0
    return dict(get_unread_message_count=get_unread_message_count)

@bp_admin.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin/admin_dashboard.html')

@bp_admin.route('/admin/user_manager_new')
@login_required
@admin_required
def user_manager_new():
    return render_template('admin/user_manager_new.html')


@bp_admin.route('/admin/newsletter', methods=['GET', 'POST'])
@login_required
@admin_required
def newsletter():
    settings_record = GlobalSettings.query.first()
    enable_newsletter = settings_record.settings.get('enableNewsletterFeature', False) if settings_record else False

    if not enable_newsletter:
        flash('Newsletter feature is disabled.', 'warning')
        print("ADMIN NEWSLETTER: Newsletter feature is disabled.")
        return redirect(url_for('bp_admin.admin_dashboard'))
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


@bp_admin.route('/admin/whitelist', methods=['GET', 'POST'])
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

@bp_admin.route('/admin/whitelist/delete/<int:id>', methods=['POST'])
@login_required
@admin_required
def delete_whitelist(id):
    whitelist_entry = Whitelist.query.get_or_404(id)
    db.session.delete(whitelist_entry)
    db.session.commit()
    flash('Email removed from whitelist successfully!', 'success')
    return redirect(url_for('main.whitelist'))



@bp_admin.route('/admin/settings', methods=['GET', 'POST'])
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
        return render_template('admin/admin_settings.html', current_settings=current_settings)
    

@bp_admin.route('/admin/status_page')
@login_required
@admin_required
def admin_status_page():
    print("Route: /admin/status_page")
    settings_record = GlobalSettings.query.first()
    enable_server_status = settings_record.settings.get('enableServerStatusFeature', False) if settings_record else False

    if not enable_server_status:
        flash('Server Status feature is disabled.', 'warning')
        return redirect(url_for('bp_admin.admin_dashboard'))
    
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

@bp_admin.route('/admin/manage_invites', methods=['GET', 'POST'])
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

@bp_admin.route('/admin/update_invites', methods=['POST'])
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



@bp_admin.route('/admin/messaging', methods=['GET', 'POST'])
@login_required
@admin_required
def messaging():
    form = SystemMessageForm()
    if form.validate_on_submit():
        message = SystemMessage(
            type=form.type.data,
            contents=form.contents.data
        )
        db.session.add(message)
        db.session.commit()
        flash('System message created successfully!', 'success')
        return redirect(url_for('bp_admin.messaging'))
    
    messages = SystemMessage.query.order_by(SystemMessage.created_at.desc()).all()
    return render_template('admin/messaging.html', form=form, messages=messages)

@bp_admin.route('/admin/delete_message/<int:message_id>', methods=['POST'])
@login_required
@admin_required
def delete_message(message_id):
    message = SystemMessage.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()
    flash('System message deleted successfully!', 'success')
    return redirect(url_for('bp_admin.messaging'))

@bp_admin.route('/admin/file_manager')
@login_required
@admin_required
def file_manager():
    return render_template('admin/file_manager.html')

@bp_admin.route('/admin/media/list')
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

@bp_admin.route('/admin/media/upload', methods=['POST'])
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

@bp_admin.route('/admin/media/thumbnail')
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

@bp_admin.route('/admin/media/download')
@login_required
@admin_required
def media_download():
    path = request.args.get('path', '')
    full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], path.lstrip('/'))
    
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        abort(404)
    
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=True)

@bp_admin.route('/admin/media/delete', methods=['POST'])
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

@bp_admin.route('/admin/media/create_folder', methods=['POST'])
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
    


@bp_admin.route('/admin/lab_editor/<int:lab_id>', methods=['GET', 'POST'])
@bp_admin.route('/admin/lab_editor', methods=['GET', 'POST'])
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

@bp_admin.route('/admin/lab_manager', methods=['GET'])
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

@bp_admin.route('/admin/delete_lab/<int:lab_id>', methods=['POST'])
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

@bp_admin.route('/admin/get_lab/<int:lab_id>', methods=['GET'])
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

@bp_admin.route('/admin/challenge_manager', methods=['GET'])
@login_required
@admin_required
def challenge_manager():
    print("Entered challenge_manager route")
    challenges = Challenge.query.all()
    csrf_form = CsrfProtectForm()
    return render_template('admin/challenge_manager.html', challenges=challenges, form=csrf_form)

@bp_admin.route('/admin/delete_challenge/<int:challenge_id>', methods=['POST'])
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

@bp_admin.route('/admin/get_solution/<int:challenge_id>')
@login_required
@admin_required
def get_solution(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    return jsonify({'solution': challenge.solution})

@bp_admin.route('/admin/get_challenge_description/<int:challenge_id>')
@login_required
@admin_required
def get_challenge_description(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    return jsonify({'description': challenge.description})

@bp_admin.route('/admin/challenge_editor/<int:challenge_id>', methods=['GET', 'POST'])
@bp_admin.route('/admin/challenge_editor', methods=['GET', 'POST'])
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
                challenge.solution = form.solution.data  # Add this line to save the solution
                challenge.solution = form.solution.data  # New field
            else:
                challenge = Challenge(
                    name=form.name.data,
                    description=form.description.data,
                    flag_uuid=form.flag_uuid.data or str(uuid4()),
                    html_link=form.html_link.data,
                    point_value=form.point_value.data,
                    downloadable_file=form.downloadable_file.data,
                    hint=form.hint.data,
                    hint_cost=form.hint_cost.data,
                    solution=form.solution.data  # New field
                )
                db.session.add(challenge)
            
            db.session.commit()
            flash('Challenge saved successfully.', 'success')
            return redirect(url_for('bp_admin.challenge_manager'))
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
        form.solution.data = challenge.solution  # Add this line to populate the solution field

    return render_template('admin/challenge_editor.html', form=form, challenge=challenge)





@bp_admin.route('/admin/host_manager', methods=['GET'])
@login_required
@admin_required
def host_manager():
    hosts = Host.query.all()
    csrf_form = CsrfProtectForm()
    return render_template('admin/host_manager.html', hosts=hosts, form=csrf_form)

@bp_admin.route('/admin/host_editor/<int:host_id>', methods=['GET', 'POST'])
@bp_admin.route('/admin/host_editor', methods=['GET', 'POST'])
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



@bp_admin.route('/admin/backgrounds')
@login_required
@admin_required
def manage_backgrounds():
    # Scan the backgrounds directory
    backgrounds_dir = os.path.join(current_app.static_folder, 'images', 'profilebackdrops')
    if not os.path.exists(backgrounds_dir):
        os.makedirs(backgrounds_dir)
    
    # Get all JPG files
    jpg_files = [f for f in os.listdir(backgrounds_dir) if f.lower().endswith('.jpg')]
    
    # Sync with database
    for jpg_file in jpg_files:
        if not ProfileBackground.query.filter_by(filename=jpg_file).first():
            new_background = ProfileBackground(
                filename=jpg_file,
                display_name=jpg_file.replace('.jpg', '').replace('_', ' ').title()
            )
            db.session.add(new_background)
    
    # Remove entries for files that no longer exist
    for background in ProfileBackground.query.all():
        if background.filename not in jpg_files:
            db.session.delete(background)
    
    db.session.commit()
    
    # Get all backgrounds ordered by order field
    backgrounds = ProfileBackground.query.order_by(ProfileBackground.order).all()
    return render_template('admin/admin_manage_backgrounds.html', backgrounds=backgrounds)

@bp_admin.route('/admin/toggle_background/<int:background_id>', methods=['POST'])
@login_required
@admin_required
def toggle_background(background_id):
    background = ProfileBackground.query.get_or_404(background_id)
    background.enabled = not background.enabled
    db.session.commit()
    return jsonify({'success': True})