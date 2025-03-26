from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, send_file, send_from_directory, current_app
from flask_login import login_required
from modules import db, cache, mail
from modules.models import GlobalSettings, Whitelist, SystemMessage, User
from modules.forms import NewsletterForm, WhitelistForm, SystemMessageForm
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