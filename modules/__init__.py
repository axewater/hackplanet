#/modules/__init__.py
import sys, os, socket, time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_mail import Mail, Message as MailMessage
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config

from urllib.parse import urlparse
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
cache = Cache(config={'CACHE_TYPE': 'simple'})
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)


def check_postgres_port_open(host, port, retries=5, delay=2):
    """
    Checks if the PostgreSQL port is open by attempting to create a socket connection.
    If the connection attempt fails, it waits for 'delay' seconds and retries.
    
    :param host: The hostname or IP address of the PostgreSQL server.
    :param port: The port number of the PostgreSQL server.
    :param retries: Maximum number of retries.
    :param delay: Delay in seconds between retries.
    :return: True if the port is open, False otherwise.
    """
    for attempt in range(retries):
        try:
            with socket.create_connection((host, port), timeout=10):
                print(f"Connection to PostgreSQL on port {port} successful.")
                return True
        except (socket.timeout, ConnectionRefusedError):
            print(f"Connection to PostgreSQL on port {port} failed. Attempt {attempt + 1} of {retries}.")
            time.sleep(delay)
    return False



def create_app():
    global s    
    app = Flask(__name__)
    app.config.from_object(Config)
    csrf = CSRFProtect(app)
    app.config['WTF_CSRF_HEADERS'] = ['X-CSRFToken', 'X-CSRF-Token']
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/library')

    parsed_url = urlparse(app.config['SQLALCHEMY_DATABASE_URI'])
    check_postgres_port_open(parsed_url.hostname, 5432, 60, 2);
    
    db.init_app(app)

    login_manager.init_app(app)
    mail.init_app(app)
    login_manager.login_view = 'bp_login.login'
    cache.init_app(app)
    limiter.init_app(app)

    with app.app_context():
        from . import routes, models
        db.create_all()
    from modules.routes_site import site_bp
    from modules.routes_integrations import int_bp
    from modules.routes_settings import bp_settings
    from modules.routes_login import bp_login
    from modules.routes_admin import bp_admin
    from modules.routes_help import bp_help
    from modules.routes_vm import bp_vm
    from modules.routes_api import bp_api
    from modules.routes_quiz import bp_quiz

    app.register_blueprint(routes.bp)
    app.register_blueprint(site_bp)
    app.register_blueprint(int_bp)
    app.register_blueprint(bp_settings)
    app.register_blueprint(bp_login)
    app.register_blueprint(bp_admin)
    app.register_blueprint(bp_help)
    app.register_blueprint(bp_vm)
    app.register_blueprint(bp_api)
    app.register_blueprint(bp_quiz)
    return app


@login_manager.user_loader
def load_user(user_id):
    from modules.models import User
    return User.query.get(int(user_id))
