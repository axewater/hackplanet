# forms.py
import re, os
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, BooleanField, SubmitField, PasswordField, TextAreaField, RadioField, FloatField, DateTimeField, ValidationError, HiddenField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import DataRequired, Length, Optional, NumberRange, Regexp, URL,Email, EqualTo
from wtforms.widgets import TextInput
from wtforms_sqlalchemy.fields import QuerySelectMultipleField
from flask import current_app
from wtforms.widgets import ListWidget, CheckboxInput, TextArea
from wtforms.fields import URLField, DateField
from urllib.parse import urlparse

class LabForm(FlaskForm):
    name = StringField('Lab Name', validators=[DataRequired(), Length(max=128)])
    image = SelectField('Image', validators=[Optional()], choices=[])
    description = TextAreaField('Description', validators=[Optional(), Length(max=5000)])
    vpn_server = StringField('VPN Server', validators=[Optional(), Length(max=256)])
    vpn_file = StringField('VPN File', validators=[Optional(), Length(max=256)])
    submit = SubmitField('Save Lab')

    def __init__(self, *args, **kwargs):
        super(LabForm, self).__init__(*args, **kwargs)
        self.image.choices = self.get_image_choices()

    def get_image_choices(self):
        image_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'labs')
        image_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        return [('', 'Select an image')] + [(f, f) for f in image_files]
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')


class WhitelistForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Add to Whitelist')

class EditProfileForm(FlaskForm):
    avatar = FileField('Profile Avatar', validators=[
        FileAllowed(['jpg', 'png'], 'Images only!')
    ])
    

class InviteForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(message='Invalid email.')], render_kw={"placeholder": "Enter email to invite"})
    submit = SubmitField('Send Invite')

class UserDetailForm(FlaskForm):
    submit = SubmitField('Save')
    cancel = SubmitField('Cancel')
    about = TextAreaField('About')


class UserPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save')
    cancel = SubmitField('Cancel')


class NewsletterForm(FlaskForm):
    subject = StringField('Subject', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    recipients = StringField('Recipients')
    send = SubmitField('Send')

class EditUserForm(FlaskForm):

    name = SelectField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    role = StringField('Role', validators=[DataRequired()])
    state = RadioField('State', choices=[('1', 'Active'), ('0', 'Inactive')])
    avatarpath = StringField('Avatar Path', validators=[DataRequired()])
    submit = SubmitField('Save')
    
    
class UserManagementForm(FlaskForm):
    user_id = SelectField('Choose hacker', coerce=int)
    name = StringField('User Name', validators=[Length(max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    role = StringField('Role', validators=[Length(max=64)])
    state = BooleanField('Account Enabled')
    search = StringField('Search Users')
    is_email_verified = BooleanField('Email Verified', validators=[Optional()])
    about = TextAreaField('Admin Notes', validators=[Optional()])
    submit = SubmitField('Save Changes')
    delete = SubmitField('Delete User')


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create User')

    
class CsrfProtectForm(FlaskForm):
    pass

class CsrfForm(FlaskForm):
    pass 

    
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

class UserPreferencesForm(FlaskForm):
    items_per_page_choices = [
        ('16', '16'),
        ('20', '20'),
        ('50', '50'),
        ('100', '100'),
        ('500', '500'),
        ('1000', '1000')
    ]
    default_sort_choices = [
        ('name', 'Name'),
        ('rating', 'Rating'),
        ('first_release_date', 'Date Released'),
        ('date_identified', 'Date Added'),
        ('size', 'Filesize')
    ]
    default_sort_order_choices = [
        ('asc', 'Ascending'),
        ('desc', 'Descending')
    ]

    items_per_page = SelectField('Max items per Page', choices=items_per_page_choices, coerce=int)
    default_sort = SelectField('Default Sort', choices=default_sort_choices)
    default_sort_order = SelectField('Default Sort Order', choices=default_sort_order_choices)
    submit = SubmitField('Save Preferences')

class FlagSubmissionForm(FlaskForm):
    flag = StringField('Flag', validators=[DataRequired()])
    host_id = HiddenField('Host ID', validators=[DataRequired()])
    flag_type = HiddenField('Flag Type', validators=[DataRequired()])
    submit = SubmitField('Submit Flag')

class ChallengeSubmissionForm(FlaskForm):
    flag = StringField('Flag', validators=[DataRequired()])
    challenge_id = HiddenField('Challenge ID', validators=[DataRequired()])
    submit = SubmitField('Submit Flag')

class ChallengeForm(FlaskForm):
    name = StringField('Challenge Name', validators=[DataRequired(), Length(max=128)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=256)])
    flag_uuid = StringField('Flag UUID', validators=[Optional(), Length(max=36)])
    html_link = SelectField('Image', validators=[Optional()], choices=[])
    point_value = IntegerField('Point Value', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Save Challenge')

    def __init__(self, *args, **kwargs):
        super(ChallengeForm, self).__init__(*args, **kwargs)
        self.html_link.choices = self.get_image_choices()

    def get_image_choices(self):
        image_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'challenges')
        image_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        return [('', 'Select an image')] + [(f, f) for f in image_files]

    def validate_html_link(self, field):
        if field.data and not os.path.exists(os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'challenges', field.data)):
            raise ValidationError('Selected image does not exist.')

class HostForm(FlaskForm):
    name = StringField('Host Name', validators=[DataRequired(), Length(max=128)])
    os = StringField('Operating System', validators=[Optional(), Length(max=128)])
    difficulty = IntegerField('Difficulty', validators=[DataRequired(), NumberRange(min=1, max=10)])
    ip = StringField('IP Address', validators=[Optional(), Length(max=45)])
    status = BooleanField('Active')
    rating = IntegerField('Rating', validators=[Optional(), NumberRange(min=1, max=5)])
    release_date = DateField('Release Date', validators=[Optional()])
    hint = TextAreaField('Hint', validators=[Optional(), Length(max=1000)])
    lab_id = HiddenField('Lab ID')
    image_url = SelectField('Image', validators=[Optional()], choices=[])
    azure_vm_id = StringField('Azure VM ID', validators=[Optional(), Length(max=256)])
    submit = SubmitField('Save Host')

    def __init__(self, *args, **kwargs):
        super(HostForm, self).__init__(*args, **kwargs)
        self.image_url.choices = self.get_image_choices()

    def get_image_choices(self):
        image_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'hosts')
        image_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        return [('', 'Select an image')] + [(f, f) for f in image_files]

class QuizForm(FlaskForm):
    title = StringField('Quiz Title', validators=[DataRequired(), Length(max=128)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=256)])
    min_score = IntegerField('Minimum Score to Pass', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Save Quiz')

class QuestionForm(FlaskForm):
    question_text = TextAreaField('Question', validators=[DataRequired(), Length(max=256)])
    option_a = StringField('Option A', validators=[DataRequired(), Length(max=128)])
    option_b = StringField('Option B', validators=[DataRequired(), Length(max=128)])
    option_c = StringField('Option C', validators=[DataRequired(), Length(max=128)])
    option_d = StringField('Option D', validators=[DataRequired(), Length(max=128)])
    correct_answer = SelectField('Correct Answer', choices=[('A', 'A'), ('B', 'B'), ('C', 'C'), ('D', 'D')], validators=[DataRequired()])
    points = IntegerField('Points', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Save Question')
    
from modules.models import Host

class FlagForm(FlaskForm):
    type = StringField('Flag Type', validators=[DataRequired(), Length(max=128)])
    uuid = StringField('Flag UUID', validators=[DataRequired(), Length(max=36)])
    point_value = IntegerField('Point Value', validators=[DataRequired(), NumberRange(min=1)])
    host_id = SelectField('Host', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Save Flag')

    def __init__(self, *args, **kwargs):
        super(FlagForm, self).__init__(*args, **kwargs)
        self.host_id.choices = [(h.id, h.name) for h in Host.query.all()]