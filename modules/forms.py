# forms.py
import re
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, BooleanField, SubmitField, PasswordField, TextAreaField, RadioField, FloatField, DateTimeField, ValidationError, HiddenField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import DataRequired, Length, Optional, NumberRange, Regexp, URL,Email, EqualTo
from wtforms.widgets import TextInput
from wtforms_sqlalchemy.fields import QuerySelectMultipleField
from wtforms.widgets import ListWidget, CheckboxInput, TextArea
from wtforms.fields import URLField, DateField
from urllib.parse import urlparse

class LabForm(FlaskForm):
    name = StringField('Lab Name', validators=[DataRequired(), Length(max=128)])
    image = StringField('Image URL', validators=[Optional(), URL(), Length(max=256)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=5000)])
    submit = SubmitField('Save Lab')
    
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
    html_link = StringField('HTML Link', validators=[Optional(), Length(max=256)])
    point_value = IntegerField('Point Value', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Save Challenge')

class HostForm(FlaskForm):
    name = StringField('Host Name', validators=[DataRequired(), Length(max=128)])
    os = StringField('Operating System', validators=[Optional(), Length(max=128)])
    difficulty = IntegerField('Difficulty', validators=[DataRequired(), NumberRange(min=1, max=10)])
    ip = StringField('IP Address', validators=[Optional(), Length(max=45)])
    status = BooleanField('Active')
    rating = IntegerField('Rating', validators=[Optional(), NumberRange(min=1, max=5)])
    release_date = DateField('Release Date', validators=[Optional()])
    hint = TextAreaField('Hint', validators=[Optional(), Length(max=1000)])
    lab_id = SelectField('Lab', coerce=int, validators=[DataRequired()])
    image_url = StringField('Image Filename', validators=[Optional(), Length(max=256)])
    azure_vm_id = StringField('Azure VM ID', validators=[Optional(), Length(max=256)])
    submit = SubmitField('Save Host')

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