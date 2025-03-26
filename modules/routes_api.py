from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from modules import db
from modules.models import User
from sqlalchemy import func
from modules.utilities import admin_required

bp_api = Blueprint('bp_api', __name__)

@bp_api.route('/api/users')
@login_required
@admin_required
def get_users():
    search = request.args.get('search', '').lower()
    query = User.query
    if search:
        query = query.filter(
            db.or_(
                func.lower(User.name).contains(search),
                func.lower(User.email).contains(search)
            )
        )
    users = query.all()
    return jsonify([{
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'role': user.role,
        'state': user.state,
        'avatar': user.avatarpath,
        'about': user.about,
        'is_email_verified': user.is_email_verified
    } for user in users])

@bp_api.route('/api/users/<user_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
@admin_required
def manage_user(user_id):
    if request.method == 'GET':
        user = User.query.get_or_404(user_id)
        return jsonify({
            'name': user.name,
            'email': user.email,
            'role': user.role,
            'state': user.state,
            'about': user.about,
            'invite_quota': user.invite_quota,
            'is_email_verified': user.is_email_verified,
            'created': user.created.isoformat() if user.created else None,
            'lastlogin': user.lastlogin.isoformat() if user.lastlogin else None
        })
    
    elif request.method == 'PUT':
        user = User.query.get_or_404(user_id)
        data = request.json
        try:
            user.name = data['name']
            user.email = data['email']
            user.role = data['role']
            user.state = data['state']
            user.is_email_verified = data['is_email_verified']
            db.session.commit()
            return jsonify({'success': True, 'message': 'User updated successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    elif request.method == 'DELETE':
        user = User.query.get_or_404(user_id)
        try:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})

@bp_api.route('/api/users/new', methods=['POST'])
@login_required
@admin_required
def create_user():
    data = request.json
    try:
        user = User(
            name=data['name'],
            email=data['email'],
            role=data['role'],
            state=data['state']
        )
        if 'password' in data and data['password']:
            user.set_password(data['password'])
        else:
            return jsonify({'success': False, 'message': 'Password is required'}), 400
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User created successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})


@bp_api.route('/api/check_username', methods=['POST'])
@login_required
def check_username():
    data = request.get_json()
    username = data.get('username')
    if not username:
        print(f"Check username: Missing username")
        return jsonify({"error": "Missing username parameter"}), 400
    print(f"Checking username: {username}")
    existing_user = User.query.filter(func.lower(User.name) == func.lower(username)).first()
    return jsonify({"exists": existing_user is not None})


