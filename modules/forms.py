# forms.py
import re
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, BooleanField, SubmitField, PasswordField, TextAreaField, RadioField, FloatField, DateTimeField, ValidationError, HiddenField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import DataRequired, Length, Optional, NumberRange, Regexp, URL,Email, EqualTo
from wtforms.widgets import TextInput
from wtforms_sqlalchemy.fields import QuerySelectMultipleField
from wtforms.widgets import ListWidget, CheckboxInput
from wtforms.fields import URLField, DateField
from urllib.parse import urlparse

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
    user_id = SelectField('Choose pirate', coerce=int)
    name = StringField('Pirate Name', validators=[Length(max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    role = StringField('Role', validators=[Length(max=64)])
    state = BooleanField('Account Enabled')
    search = StringField('Search Users')
    is_email_verified = BooleanField('Email Verified', validators=[Optional()])
    about = TextAreaField('Admin Notes', validators=[Optional()])
    submit = SubmitField('Save Changes')
    delete = SubmitField('Walk the plank!')


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