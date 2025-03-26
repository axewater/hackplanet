from flask import Blueprint, request, jsonify, abort
from flask_login import login_required, current_user
from modules import db
from modules.models import User, Host, HostReview
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

@bp_api.route('/api/host/<int:host_id>/review', methods=['POST'])
@login_required
def submit_host_review(host_id):
    """API endpoint to submit a review for a host"""
    host = Host.query.get_or_404(host_id)
    
    # Verify the user has completed both flags for this host
    if not host.has_completed_both_flags(current_user.id):
        return jsonify({
            'success': False,
            'message': 'You must complete both user and root flags before reviewing this host'
        }), 403
    
    data = request.json
    
    # Validate rating values
    for rating_type in ['difficulty', 'fun', 'realism']:
        rating = data.get(f'{rating_type}_rating')
        if not rating or not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify({
                'success': False,
                'message': f'Invalid {rating_type} rating. Must be an integer between 1 and 5.'
            }), 400
    
    # Check if user has already reviewed this host
    existing_review = HostReview.query.filter_by(user_id=current_user.id, host_id=host_id).first()
    
    try:
        if existing_review:
            # Update existing review
            existing_review.difficulty_rating = data['difficulty_rating']
            existing_review.fun_rating = data['fun_rating']
            existing_review.realism_rating = data['realism_rating']
            existing_review.comment = data.get('comment', '')
            message = 'Review updated successfully'
        else:
            # Create new review
            review = HostReview(
                user_id=current_user.id,
                host_id=host_id,
                difficulty_rating=data['difficulty_rating'],
                fun_rating=data['fun_rating'],
                realism_rating=data['realism_rating'],
                comment=data.get('comment', '')
            )
            db.session.add(review)
            message = 'Review submitted successfully'
        
        db.session.commit()
        return jsonify({'success': True, 'message': message})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@bp_api.route('/api/host/<int:host_id>/reviews', methods=['GET'])
@login_required
def get_host_reviews(host_id):
    """API endpoint to get reviews for a host"""
    host = Host.query.get_or_404(host_id)
    
    # Get all reviews for this host
    reviews = HostReview.query.filter_by(host_id=host_id).all()
    
    # Format the reviews
    formatted_reviews = []
    for review in reviews:
        user = User.query.get(review.user_id)
        formatted_reviews.append({
            'id': review.id,
            'user_name': user.name,
            'difficulty_rating': review.difficulty_rating,
            'fun_rating': review.fun_rating,
            'realism_rating': review.realism_rating,
            'comment': review.comment,
            'created_at': review.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    # Return the reviews along with average ratings
    return jsonify({'success': True, 'reviews': formatted_reviews})

@bp_api.route('/api/host/<int:host_id>/user_review', methods=['GET'])
@login_required
def get_user_host_review(host_id):
    """API endpoint to get the current user's review for a host"""
    host = Host.query.get_or_404(host_id)
    
    # Get the user's review for this host
    review = HostReview.query.filter_by(host_id=host_id, user_id=current_user.id).first()
    
    if not review:
        return jsonify({'success': False, 'message': 'No review found'})
    
    # Format the review
    formatted_review = {
        'id': review.id,
        'difficulty_rating': review.difficulty_rating,
        'fun_rating': review.fun_rating,
        'realism_rating': review.realism_rating,
        'comment': review.comment
    }
    
    return jsonify({'success': True, 'review': formatted_review})
