# modules/routes_ctf.py
from flask import Flask, render_template, flash, current_user
from sqlalchemy.orm import joinedload
from .models import User, Lab, Host, Flag, Challenge

@bp.route('/ctf')
def ctf_home():
    return render_template('site/ctf.html')

@bp.route('/ctf/leaderboard')
def leaderboard():
    # Fetch user scores from the database
    print("Fetching user scores from the database...")
    users = User.query.with_entities(User.name, User.score_total, User.avatarpath).order_by(User.score_total.desc()).all()
    print(f"Users: {users} avatarpath: {users[0].avatarpath}")
    return render_template('site/leaderboard.html', users=users)

@bp.route('/ctf/hacking_labs')
def hacking_labs():
    # Fetch labs and their hosts from the database
    labs = Lab.query.options(joinedload(Lab.hosts).joinedload(Host.flags)).all()

    # Check if the user is an admin
    is_admin = current_user.role == 'admin'

    return render_template('site/hacking_labs.html', labs=labs, is_admin=is_admin)

@bp.route('/ctf/challenges')
def challenges():
    # Fetch challenges from the database
    challenges = Challenge.query.all()
    return render_template('site/challenges.html', challenges=challenges)
