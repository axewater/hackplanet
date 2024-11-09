# modules/models.py
from argon2.exceptions import VerifyMismatchError
from modules import db
from sqlalchemy import Boolean
from sqlalchemy import Table, Column, Integer, String, ForeignKey, Float, DateTime, Enum, func
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
    score_total = db.Column(db.Integer, default=0)
    preferences = db.relationship('UserPreference', uselist=False, back_populates='user', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        if self.password_hash.startswith('$argon2'):
            try:
                return ph.verify(self.password_hash, password)
            except VerifyMismatchError:
                return False
        else:
            return check_password_hash(self.password_hash, password)
        
    def rehash_password(self, password):
        if not self.password_hash.startswith('$argon2'):
            self.password_hash = ph.hash(password)

    def calculate_total_score(self):
        from modules.models import ChallengesObtained, UserQuizProgress, FlagsObtained, Flag
        challenge_score = db.session.query(func.sum(Challenge.point_value)).join(ChallengesObtained).filter(ChallengesObtained.user_id == self.id, ChallengesObtained.completed == True).scalar() or 0
        hint_cost = db.session.query(func.sum(Challenge.hint_cost)).join(ChallengesObtained).filter(ChallengesObtained.user_id == self.id, ChallengesObtained.used_hint == True, ChallengesObtained.completed == True).scalar() or 0
        quiz_score = db.session.query(func.sum(UserQuizProgress.score)).filter(UserQuizProgress.user_id == self.id).scalar() or 0
        flag_score = db.session.query(func.sum(Flag.point_value)).join(FlagsObtained).filter(FlagsObtained.user_id == self.id).scalar() or 0
        return challenge_score - hint_cost + quiz_score + flag_score

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
    theme = db.Column(db.String(50), default='default')

    user = db.relationship('User', back_populates='preferences')

    def __init__(self, user_id, theme='default'):
        self.user_id = user_id
        self.theme = theme

class GlobalSettings(db.Model):
    __tablename__ = 'global_settings'

    id = db.Column(db.Integer, primary_key=True)
    settings = db.Column(JSONEncodedDict)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<GlobalSettings id={self.id}, last_updated={self.last_updated}>'



class Lab(db.Model):
    __tablename__ = 'labs'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    image = db.Column(db.String(256), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    description = db.Column(db.String(5000), nullable=True)
    hosts = relationship('Host', backref='lab', lazy=True)
    vpn_file = db.Column(db.String(256), nullable=True)
    vpn_server = db.Column(db.String(256), nullable=True)  # New field for VPN server
    vpn_status = db.Column(db.Boolean, default=False)  # New field for VPN status

    @property
    def host_count(self):
        return len(self.hosts)

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
    flags = relationship('Flag', backref='host', lazy=True, cascade="all, delete-orphan")
    rating = db.Column(db.Integer, nullable=True)
    release_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    hint = db.Column(db.String(1000), nullable=True)
    lab_id = db.Column(db.Integer, db.ForeignKey('labs.id'), nullable=False)
    image_url = db.Column(db.String(256), nullable=True)
    azure_vm_id = db.Column(db.String(256), nullable=True)

    def __repr__(self):
        return f"<Host id={self.id}, name={self.name}, difficulty={self.difficulty}>"

    @property
    def image(self):
        return self.image_url





class Challenge(db.Model):
    __tablename__ = 'challenges'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(2048), nullable=True)
    flag_uuid = db.Column(db.String(128), unique=True, nullable=False, default=str(uuid4()))
    html_link = db.Column(db.String(256), nullable=True)
    point_value = db.Column(db.Integer, nullable=False)
    downloadable_file = db.Column(db.String(256), nullable=True)
    hint = db.Column(db.String(512), nullable=True)
    hint_cost = db.Column(db.Integer, nullable=True)
    solution = db.Column(db.Text, nullable=True)  # New field for solution

    def __repr__(self):
        return f"<Challenge id={self.id}, name={self.name}, flag_uuid={self.flag_uuid}, point_value={self.point_value}>"


class Flag(db.Model):
    __tablename__ = 'flags'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(128), nullable=False)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=str(uuid4()))
    point_value = db.Column(db.Integer, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f"<Flag id={self.id}, type={self.type}, uuid={self.uuid}, point_value={self.point_value}>"
    
class UserProgress(db.Model):
    __tablename__ = 'user_progress'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    score_total = db.Column(db.Integer, nullable=False, default=0)
    user = db.relationship('User', backref=db.backref('progress', uselist=False))

    def __init__(self, user_id, obtained_flags=None):
        self.user_id = user_id
        self.obtained_flags = obtained_flags or {}

    def __repr__(self):
        return f"<UserProgress id={self.id}, user_id={self.user_id}>"

class FlagsObtained(db.Model):
    __tablename__ = 'flags_obtained'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    flag_id = db.Column(db.Integer, db.ForeignKey('flags.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('flags_obtained', lazy=True))
    flag = db.relationship('Flag', backref=db.backref('users_obtained', lazy=True))

    def __repr__(self):
        return f"<FlagsObtained id={self.id}, user_id={self.user_id}, flag_id={self.flag_id}>"
    
class ChallengesObtained(db.Model):
    __tablename__ = 'challenges_obtained'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id'), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    used_hint = db.Column(db.Boolean, default=False, nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    user = db.relationship('User', backref=db.backref('challenges_obtained', lazy=True))
    challenge = db.relationship('Challenge', backref=db.backref('users_obtained', lazy=True))

    def __repr__(self):
        return f"<ChallengesObtained id={self.id}, user_id={self.user_id}, challenge_id={self.challenge_id}, completed_at={self.completed_at}, used_hint={self.used_hint}, completed={self.completed}>"

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(256))
    min_score = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(256), nullable=True)
    sequential = db.Column(db.Boolean, default=False)
    questions = db.relationship('Question', backref='quiz', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Quiz id={self.id}, title={self.title}, sequential={self.sequential}>"

class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    question_text = db.Column(db.String(256), nullable=False)
    option_a = db.Column(db.String(128), nullable=False)
    option_b = db.Column(db.String(128), nullable=False)
    option_c = db.Column(db.String(128), nullable=False)
    option_d = db.Column(db.String(128), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)
    points = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(256), nullable=True)
    explanation = db.Column(db.Text, nullable=True)  # New field for explanation

    def __repr__(self):
        return f"<Question id={self.id}, quiz_id={self.quiz_id}>"

class UserQuizProgress(db.Model):
    __tablename__ = 'user_quiz_progress'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False, default=0)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)
    current_question = db.Column(db.Integer, default=0)
    user = db.relationship('User', backref=db.backref('quiz_progress', lazy=True))
    quiz = db.relationship('Quiz', backref=db.backref('user_progress', lazy=True))

    def __repr__(self):
        return f"<UserQuizProgress id={self.id}, user_id={self.user_id}, quiz_id={self.quiz_id}, score={self.score}, current_question={self.current_question}>"

class UserQuestionProgress(db.Model):
    __tablename__ = 'user_question_progress'
    id = db.Column(db.Integer, primary_key=True)
    user_quiz_progress_id = db.Column(db.Integer, db.ForeignKey('user_quiz_progress.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    answered = db.Column(db.Boolean, default=False)
    correct = db.Column(db.Boolean, default=False)
    user_quiz_progress = db.relationship('UserQuizProgress', backref=db.backref('question_progress', lazy=True))
    question = db.relationship('Question', backref=db.backref('user_progress', lazy=True))
    user_answer = db.Column(db.String(1), nullable=True)

    def __repr__(self):
        return f"<UserQuestionProgress id={self.id}, user_quiz_progress_id={self.user_quiz_progress_id}, question_id={self.question_id}, answered={self.answered}, correct={self.correct}, user_answer={self.user_answer}>"

class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    file_attachment = db.Column(db.String(256), nullable=True)
    image = db.Column(db.String(256), nullable=True)
    tags = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    purchase_url = db.Column(db.String(512), nullable=True)  # New field for purchase URL

    def __repr__(self):
        return f"<Course id={self.id}, name={self.name}>"

    @property
    def tag_list(self):
        return [tag.strip() for tag in self.tags.split(',')] if self.tags else []

class SystemMessage(db.Model):
    __tablename__ = 'system_messages'

    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=str(uuid4()))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    type = db.Column(db.String(128), nullable=False)
    contents = db.Column(db.Text, nullable=False)

    def __init__(self, type, contents):
        self.type = type
        self.contents = contents

    def __repr__(self):
        return f"<SystemMessage id={self.id}, type={self.type}, created_at={self.created_at}, uuid={self.uuid}>"
