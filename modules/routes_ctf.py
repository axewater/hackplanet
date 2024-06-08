# modules/routes_ctf.py
from flask import Flask, render_template, flash, current_user, request, redirect, url_for
from sqlalchemy.orm import joinedload
from .models import User, Lab, Host, Flag, Challenge
from .forms import FlagSubmissionForm
from sqlalchemy.exc import SQLAlchemyError

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

    # Instantiate the FlagSubmissionForm
    form = FlagSubmissionForm()

    return render_template('site/hacking_labs.html', labs=labs, is_admin=is_admin, form=form)

@bp.route('/ctf/challenges')
def challenges():
    # Fetch challenges from the database
    challenges = Challenge.query.all()
    return render_template('site/challenges.html', challenges=challenges)

@bp.route('/ctf/submit_flag', methods=['POST'])
def submit_flag():
    form = FlagSubmissionForm()
    if form.validate_on_submit():
        flag = form.flag.data
        host_id = form.host_id.data
        flag_type = form.flag_type.data

        try:
            # Retrieve the flag from the database
            flag_record = Flag.query.filter_by(host_id=host_id, type=flag_type).first()
            if flag_record and flag_record.uuid == flag:
                # Flag is correct, update user progress and score
                user_progress = UserProgress.query.filter_by(user_id=current_user.id).first()
                if not user_progress:
                    user_progress = UserProgress(user_id=current_user.id, obtained_flags={}, score_total=0)

                obtained_flags = user_progress.obtained_flags or {}
                if flag_record.uuid not in obtained_flags:
                    obtained_flags[flag_record.uuid] = True
                    user_progress.obtained_flags = obtained_flags
                    user_progress.score_total += flag_record.point_value
                    current_user.score_total += flag_record.point_value

                    db.session.add(user_progress)
                    db.session.commit()

                    flash('Flag submitted successfully!', 'success')
                else:
                    flash('Flag has already been submitted.', 'warning')
            else:
                flash('Invalid flag.', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')

    return redirect(url_for('ctf.hacking_labs'))
