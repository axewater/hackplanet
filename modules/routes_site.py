# modules/routes_site.py
from flask import Blueprint, render_template, request, redirect, url_for, current_app, send_from_directory
from flask_login import login_required, logout_user
import os
site_bp = Blueprint('site', __name__)






@site_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('bp_login.login'))


@site_bp.route('/', methods=['GET', 'POST'])
@site_bp.route('/index', methods=['GET', 'POST'])
def index():
    return redirect(url_for('bp_login.login'))



@site_bp.route('/favicon.ico')
def favicon():
    favidir = "icons"
    full_dir = os.path.join(current_app.static_folder, favidir)
    print(f"Full dir: {full_dir}" if os.path.isdir(full_dir) else f"Dir not found: {full_dir}")
    return send_from_directory(full_dir, 'favicon.ico', mimetype='image/vnd.microsoft.icon')




