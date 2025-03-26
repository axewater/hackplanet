from flask import render_template, redirect, url_for, flash, request, current_app, Blueprint
from flask_login import login_required, current_user
from PIL import Image as PILImage
from uuid import uuid4
import os
from modules import db

from werkzeug.utils import secure_filename
from modules.models import User, UserPreference, ProfileBackground, SystemMessage
from modules.forms import CsrfForm, EditProfileForm, UserPasswordForm, UserPreferencesForm
from modules.utilities import admin_required, square_image

bp_settings = Blueprint('bp_settings', __name__)

@bp_settings.context_processor
def utility_processor():
    def get_unread_message_count():
        if current_user.is_authenticated:
            return SystemMessage.query.filter(
                ~SystemMessage.read_by.contains(current_user)
            ).count()
        return 0
    return dict(get_unread_message_count=get_unread_message_count)


@bp_settings.route('/settings/settings_backdrop', methods=['GET', 'POST'])
@login_required
def settings_backdrop():
    form = CsrfForm()
    backgrounds = ProfileBackground.query.filter_by(enabled=True).order_by(ProfileBackground.order).all()
    current_backdrop_id = current_user.preferences.background_id if current_user.preferences else None
    
    if form.validate_on_submit():
        background_id = request.form.get('background_id')
        if background_id:
            if not current_user.preferences:
                current_user.preferences = UserPreference(user_id=current_user.id)
            current_user.preferences.background_id = int(background_id)
            db.session.commit()
            flash('Background updated successfully!', 'success')
            return redirect(url_for('bp_settings.settings_backdrop'))
    
    return render_template('settings/settings_backdrop.html', 
                         backgrounds=backgrounds,
                         current_backdrop_id=current_backdrop_id,
                         form=form)


@bp_settings.route('/settings_profile_edit', methods=['GET', 'POST'])
@login_required
def settings_profile_edit():
    print("Route: Settings profile edit")
    form = EditProfileForm()

    if form.validate_on_submit():
        avatar_source = form.avatar_source.data
        
        # Handle background selection
        if form.background.data:
            if not current_user.preferences:
                current_user.preferences = UserPreference(user_id=current_user.id)
            current_user.preferences.background_id = int(form.background.data)
        
        if avatar_source == 'gallery' and form.gallery_avatar.data:
            # Using gallery avatar
            selected_avatar = form.gallery_avatar.data.replace('\\', '/')
            gallery_path = 'library/avatars_users/gallery/' + selected_avatar
            
            # Update user's avatar path to point to the gallery image
            current_user.avatarpath = gallery_path
            db.session.commit()
            flash('Avatar updated successfully!', 'success')
            return redirect(url_for('bp_settings.settings_profile_edit'))
            
        elif avatar_source == 'custom' and form.avatar.data:
            # Handle custom avatar upload
            file = form.avatar.data
            # Ensure UPLOAD_FOLDER exists
            upload_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'avatars_users')
            if not os.path.exists(upload_folder):
                try:
                    # Safe check to avoid creating 'static' directly
                    os.makedirs(upload_folder, exist_ok=True)
                except Exception as e:
                    print(f"Error creating upload directory: {e}")
                    flash("Error processing request. Please try again.", 'error')
                    return redirect(url_for('bp_settings.settings_profile_edit'))

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

        return redirect(url_for('bp_settings.settings_profile_edit'))

    print("Form validation failed" if request.method == 'POST' else "Settings profile Form rendering")

    for field, errors in form.errors.items():
        for error in errors:
            print(f"Error in field '{getattr(form, field).label.text}': {error}")
            flash(f"Error in field '{getattr(form, field).label.text}': {error}", 'error')

    return render_template('settings/settings_profile_edit.html', form=form, avatarpath=current_user.avatarpath)

@bp_settings.route('/settings_profile_view', methods=['GET'])
@login_required
def settings_profile_view():
    print("Route: Settings profile view")
    return render_template('settings/settings_profile_view.html')

@bp_settings.route('/settings_password', methods=['GET', 'POST'])
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
            return redirect(url_for('bp_settings.account_pw'))
        except Exception as e:
            db.session.rollback()
            print('An error occurred while changing the password:', str(e))
            flash('An error occurred. Please try again.', 'error')

    return render_template('settings/settings_password.html', title='Change Password', form=form, user=user)

@bp_settings.route('/settings_panel', methods=['GET', 'POST'])
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
        return redirect(url_for('bp_login.restricted'))
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


