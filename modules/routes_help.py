from flask import Blueprint, render_template
from flask_login import login_required, current_user
from modules.models import SystemMessage
from modules.utilities import admin_required

bp_help = Blueprint('bp_help', __name__)

@bp_help.context_processor
def utility_processor():
    def get_unread_message_count():
        if current_user.is_authenticated:
            return SystemMessage.query.filter(
                ~SystemMessage.read_by.contains(current_user)
            ).count()
        return 0
    return dict(get_unread_message_count=get_unread_message_count)

@bp_help.route('/admin/help')
@login_required
@admin_required
def admin_help():
    return render_template('admin/admin_help.html')

@bp_help.route('/help')
@login_required
def help_page():
    return render_template('help/overview.html')

@bp_help.route('/help/getting_started')
@login_required
def help_getting_started():
    return render_template('help/getting_started.html')

@bp_help.route('/help/ctf_challenges')
@login_required
def help_ctf_challenges():
    return render_template('help/ctf_challenges.html')

@bp_help.route('/help/labs')
@login_required
def help_labs():
    return render_template('help/labs.html')

@bp_help.route('/help/study_room')
@login_required
def help_study_room():
    return render_template('help/study_room.html')

@bp_help.route('/help/scoring')
@login_required
def help_scoring():
    return render_template('help/scoring.html')

@bp_help.route('/help/platform_features')
@login_required
def help_platform_features():
    return render_template('help/platform_features.html')