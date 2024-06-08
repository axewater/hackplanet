# modules/models.py
from modules import db
from sqlalchemy import Boolean
from sqlalchemy import Table, Column, Integer, String, ForeignKey, Float, DateTime, Enum
from sqlalchemy.dialects.sqlite import TEXT as SQLite_TEXT
from sqlalchemy.orm import relationship
from sqlalchemy.types import TypeDecorator, TEXT
from sqlalchemy.types import Enum as SQLEnum
from werkzeug.security import generate_password_hash, check_password_hash
from argon2 import PasswordHasher

from datetime import datetime, timedelta
import uuid, json
from uuid import uuid4
from datetime import datetime
from enum import Enum as PyEnum


ph = PasswordHasher()

class JSONEncodedDict(TypeDecorator):
    impl = TEXT

    def process_bind_param(self, value, dialect):
        if value is not None:
            try:
                return json.dumps(value)
            except (TypeError, ValueError) as e:
                print(f"Error serializing JSON: {e}")
                return None
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            try:
                return json.loads(value)
            except (TypeError, ValueError) as e:
                print(f"Error deserializing JSON: {e}")
                return {}
        return value


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(64), nullable=False)
    state = db.Column(db.Boolean, default=True)
    about = db.Column(db.String(256), unique=True, nullable=True)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    lastlogin = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.String(36), unique=True, nullable=False, default=str(uuid4()))
    avatarpath = db.Column(db.String(256), default='newstyle/avatar_default.jpg')
    is_email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(256), nullable=True)
    password_reset_token = db.Column(db.String(256), nullable=True)
    token_creation_time = db.Column(db.DateTime, nullable=True)
    invite_quota = db.Column(db.Integer, default=0)
    invited_by = Column(String(36), ForeignKey('users.user_id'), nullable=True)
    score_total = db.Column(db.Integer, default=0)
    
    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        if self.password_hash.startswith('$argon2'):
            try:
                return ph.verify(self.password_hash, password)
            except argon2_exceptions.VerifyMismatchError:
                return False
        else:
            return check_password_hash(self.password_hash, password)
        
    def rehash_password(self, password):
        if not self.password_hash.startswith('$argon2'):
            self.password_hash = ph.hash(password)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f"<User id={self.id}, name={self.name}, email={self.email}>"


class Whitelist(db.Model):
    __tablename__ = 'whitelist'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

class UserPreference(db.Model):
    __tablename__ = 'user_preferences'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    items_per_page = db.Column(db.Integer, default=20)
    default_sort = db.Column(db.String(50), default='name')
    default_sort_order = db.Column(db.String(4), default='asc')

    user = db.relationship('User', backref=db.backref('preferences', uselist=False))

class GlobalSettings(db.Model):
    __tablename__ = 'global_settings'

    id = db.Column(db.Integer, primary_key=True)
    settings = db.Column(JSONEncodedDict)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<GlobalSettings id={self.id}, last_updated={self.last_updated}>'


class InviteToken(db.Model):
    __tablename__ = 'invite_tokens'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(256), nullable=False, unique=True)
    creator_user_id = db.Column(db.String(36), db.ForeignKey('users.user_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(days=2), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'<InviteToken {self.token}, Creator: {self.creator_user_id}, Expires: {self.expires_at}>'


class Lab(db.Model):
    __tablename__ = 'labs'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    image = db.Column(db.String(256), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    description = db.Column(db.String(5000), nullable=True)
    hosts = relationship('Host', backref='lab', lazy=True)
    vpn_file = db.Column(db.String(256), nullable=True)

    def __repr__(self):
        return f"<Lab id={self.id}, name={self.name}, date_created={self.date_created}>"





class Host(db.Model):
    __tablename__ = 'hosts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    os = db.Column(db.String(128), nullable=True)
    difficulty = db.Column(db.Integer, nullable=False)
    ip = db.Column(db.String(45), nullable=True)
    status = db.Column(db.Boolean, default=True)
    flags = relationship('Flag', backref='host', lazy=True)
    rating = db.Column(db.Integer, nullable=True)
    release_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    hint = db.Column(db.String(1000), nullable=True)
    lab_id = db.Column(db.Integer, db.ForeignKey('labs.id'), nullable=False)
    image_url = db.Column(db.String(256), nullable=True)
    

    def __repr__(self):
        return f"<Host id={self.id}, name={self.name}, difficulty={self.difficulty}>"





class Challenge(db.Model):
    __tablename__ = 'challenges'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(256), nullable=True)
    flag_uuid = db.Column(db.String(36), unique=True, nullable=False, default=str(uuid4()))
    html_link = db.Column(db.String(256), nullable=True)
    point_value = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"<Challenge id={self.id}, name={self.name}, flag_uuid={self.flag_uuid}, point_value={self.point_value}>"


class Flag(db.Model):
    __tablename__ = 'flags'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(128), nullable=False)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=str(uuid4()))
    point_value = db.Column(db.Integer, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)

    def __repr__(self):
        return f"<Flag id={self.id}, type={self.type}, uuid={self.uuid}, point_value={self.point_value}>"
    
class UserProgress(db.Model):
    __tablename__ = 'user_progress'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    completed_challenges = db.Column(JSONEncodedDict, nullable=True)
    obtained_flags = db.Column(JSONEncodedDict, nullable=True)
    score_total = db.Column(db.Integer, nullable=False, default=0)
    user = db.relationship('User', backref=db.backref('progress', uselist=False))

    def __repr__(self):
        return f"<UserProgress id={self.id}, user_id={self.user_id}>"
