# modules/routes_site.py
from flask import Blueprint, render_template, request, redirect, url_for, current_app, jsonify
from flask_login import login_required, logout_user
import os
import requests


int_bp = Blueprint('int_bp', __name__)

@int_bp.route('/admin/integrations')
@login_required
def integrations():
    print("Route: /admin/integrations")
    hpagent_url = current_app.config['HPAGENT_API_URL']
    hpagent_api_key = current_app.config['HPAGENT_API_KEY']
    
    # Connect to HPAgent API and get JSON response
    try:
        headers = {'Authorization': f'Bearer {hpagent_api_key}'}
        response = requests.get(hpagent_url, headers=headers)
        response.raise_for_status()
        api_results = response.json()
    except requests.RequestException as e:
        api_results = {'error': str(e)}
    
    return render_template('admin/integrations.html', hpagent_url=hpagent_url, hpagent_api_key=hpagent_api_key, api_results=api_results)


