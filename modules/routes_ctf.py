# modules/routes_ctf.py
from flask import Flask, render_template, flash


@bp.route('/ctf')
def ctf_home():
    return render_template('site/ctf.html')

@bp.route('/ctf/leaderboard')
def leaderboard():
    # Fetch user scores from the database
    users = User.query.order_by(User.score_total.desc()).all()
    return render_template('site/leaderboard.html', users=users)

@bp.route('/ctf/hacking_labs')
def hacking_labs():
    # Fetch labs and their hosts from the database
    labs = Lab.query.all()
    return render_template('site/hacking_labs.html', labs=labs)

@bp.route('/ctf/challenges')
def challenges():
    # Fetch challenges from the database
    challenges = Challenge.query.all()
    return render_template('site/challenges.html', challenges=challenges)