# modules/routes_ctf.py

from flask import Flask, render_template, request, Blueprint, jsonify
from flask_login import current_user
from flask_wtf import FlaskForm
from sqlalchemy.orm import joinedload
from modules import db, mail, cache
from functools import wraps
from uuid import uuid4
from modules.forms import (
FlagSubmissionForm
)
from modules.models import (
    Lab, Host, Flag, UserProgress
)

@bp.route('/ctf/submit_flag_api', methods=['GET'])
def submit_flag_api():
    flag = request.args.get('flag')
    flag_type = request.args.get('flag_type')
    host_id = request.args.get('host_id')

    if not flag or not flag_type or not host_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    print(f"Received flag: {flag}, host_id: {host_id}, flag_type: {flag_type}")
    flag_record = Flag.query.filter_by(host_id=host_id, type=flag_type).first()

    try:
        if flag_record and flag_record.uuid == flag:
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

                return jsonify({'host_id': host_id, 'flag_type': flag_type, 'result': 'passed'})
            else:
                return jsonify({'error': 'Sorry you already submitted this flag'}), 400
        else:
            return jsonify({'error': 'Invalid flag'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'host_id': host_id, 'flag_type': flag_type, 'result': 'failed'})

@bp.route('/ctf/hacking_labs')
def hacking_labs():
    # Fetch labs and their hosts from the database
    labs = Lab.query.options(joinedload(Lab.hosts).joinedload(Host.flags)).all()
    print(f"Labs: {labs} host: {labs[0].hosts} flags: {labs[0].hosts[0].flags}")
    # Check if the user is an admin
    is_admin = current_user.role == 'admin'

    # Instantiate the FlagSubmissionForm
    form = FlagSubmissionForm()

    return render_template('site/hacking_labs.html', labs=labs, is_admin=is_admin, form=form)