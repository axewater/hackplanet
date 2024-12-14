# forms.py
import re, os
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, BooleanField, SubmitField, PasswordField, TextAreaField, RadioField, FloatField, DateTimeField, ValidationError, HiddenField
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms.validators import DataRequired, Length, Optional, NumberRange, Regexp, URL,Email, EqualTo
from wtforms.widgets import TextInput
from wtforms_sqlalchemy.fields import QuerySelectMultipleField

class ThemeUploadForm(FlaskForm):
    theme_zip = FileField('Theme ZIP File', validators=[
        FileRequired(),
        FileAllowed(['zip'], 'ZIP files only!')
    ])
    submit = SubmitField('Upload Theme')
from flask import current_app
from wtforms.widgets import ListWidget, CheckboxInput, TextArea
from wtforms.fields import URLField, DateField
from urllib.parse import urlparse

class RSSConfigForm(FlaskForm):
    feed_title = StringField('Feed Title', validators=[DataRequired(), Length(max=128)], 
                           render_kw={"placeholder": "Enter feed title"})
    feed_description = TextAreaField('Feed Description', 
                                   validators=[Optional(), Length(max=256)],
                                   render_kw={"placeholder": "Enter feed description"})
    feed_limit = IntegerField('Feed Item Limit', 
                            validators=[DataRequired(), NumberRange(min=1, max=100)], 
                            default=50,
                            render_kw={"placeholder": "Enter item limit (1-100)"})
    enable_flag_wins = BooleanField('Show Flag Wins', default=True)
    enable_challenge_wins = BooleanField('Show Challenge Wins', default=True)
    enable_quiz_completions = BooleanField('Show Quiz Completions', default=True)
    enable_information_messages = BooleanField('Show Information Messages', default=True)
    submit = SubmitField('Save RSS Configuration')

class SystemMessageForm(FlaskForm):
    type = SelectField('Message Type', choices=[
        ('info', 'Information'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('success', 'Success')
    ], validators=[DataRequired()])
    contents = TextAreaField('Message Contents', validators=[DataRequired(), Length(max=1000)])
    submit = SubmitField('Create Message')

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
    avatar_source = RadioField('Avatar Source', choices=[
        ('gallery', 'Choose from Gallery'),
        ('custom', 'Upload Custom Avatar')
    ], default='gallery')
    avatar = FileField('Custom Avatar', validators=[
        FileAllowed(['jpg', 'png'], 'Images only!')
    ])
    gallery_avatar = SelectField('Gallery Avatar', choices=[], validators=[Optional()])
    background = SelectField('Profile Background', choices=[], validators=[Optional()])

    def __init__(self, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.gallery_avatar.choices = self.get_gallery_choices()
        self.background.choices = self.get_background_choices()

    def get_background_choices(self):
        from modules.models import ProfileBackground
        backgrounds = ProfileBackground.query.filter_by(enabled=True).order_by(ProfileBackground.order).all()
        return [('', 'Select a background')] + [(str(bg.id), bg.display_name or bg.filename) for bg in backgrounds]

    def __init__(self, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.gallery_avatar.choices = self.get_gallery_choices()

    def get_gallery_choices(self):
        gallery_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'avatars_users', 'gallery')
        if not os.path.exists(gallery_path):
            return [('', 'No gallery avatars available')]
        # Filter out thumbnail files and only include .jpg files
        avatars = [f for f in os.listdir(gallery_path) 
                  if f.lower().endswith('.jpg') and '_thumbnail' not in f]
        # Convert paths to use forward slashes
        return [('', 'Select an avatar')] + [(f.replace('\\', '/'), f) for f in sorted(avatars)]

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


class CsrfProtectForm(FlaskForm):
    pass

class CsrfForm(FlaskForm):
    pass 

    
class RegistrationForm(FlaskForm):
    username = StringField('Choose your Hacker handle', validators=[DataRequired()])
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

class UserThemePreferencesForm(FlaskForm):
    theme = SelectField('Theme', choices=[])
    submit = SubmitField('Save Theme Preference')

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
    description = TextAreaField('Description', validators=[Optional(), Length(max=2048)])
    flag_uuid = StringField('Flag UUID', validators=[Optional(), Length(max=128)])
    html_link = SelectField('Image', validators=[Optional()], choices=[])
    point_value = IntegerField('Point Value', validators=[DataRequired(), NumberRange(min=1)])
    downloadable_file = SelectField('Downloadable File', validators=[Optional()], choices=[])
    hint = TextAreaField('Hint', validators=[Optional(), Length(max=512)])
    hint_cost = IntegerField('Hint Cost', validators=[Optional(), NumberRange(min=0)])
    solution = TextAreaField('Solution', validators=[Optional()])  # New field for solution
    submit = SubmitField('Save Challenge')

    def __init__(self, *args, **kwargs):
        super(ChallengeForm, self).__init__(*args, **kwargs)
        self.html_link.choices = self.get_image_choices()
        self.downloadable_file.choices = self.get_file_choices()

    def get_image_choices(self):
        image_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'challenges')
        image_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        return [('', 'Select an image')] + [(f, f) for f in image_files]

    def get_file_choices(self):
        file_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'challenges')
        allowed_extensions = current_app.config['ALLOWED_EXTENSIONS']
        files = [f for f in os.listdir(file_folder) if f.lower().split('.')[-1] in allowed_extensions]
        return [('', 'Select a file')] + [(f, f) for f in files]

    def validate_html_link(self, field):
        if field.data and not os.path.exists(os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'challenges', field.data)):
            raise ValidationError('Selected image does not exist.')

    def validate_downloadable_file(self, field):
        if field.data and not os.path.exists(os.path.join(current_app.config['UPLOAD_FOLDER'], 'challenges', field.data)):
            raise ValidationError('Selected file does not exist.')

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
    image = SelectField('Image', validators=[Optional()], choices=[])
    sequential = BooleanField('Sequential Questions', default=False)
    submit = SubmitField('Save Quiz')

    def __init__(self, *args, **kwargs):
        super(QuizForm, self).__init__(*args, **kwargs)
        self.image.choices = self.get_image_choices()

    def get_image_choices(self):
        image_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'quizes')
        image_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        image_files.sort()  # Sort the image files alphabetically
        return [('', 'Select an image')] + [(f, f) for f in image_files]

class QuestionForm(FlaskForm):
    question_text = TextAreaField('Question', validators=[DataRequired(), Length(max=256)])
    option_a = StringField('Option A', validators=[DataRequired(), Length(max=128)])
    option_b = StringField('Option B', validators=[DataRequired(), Length(max=128)])
    option_c = StringField('Option C', validators=[DataRequired(), Length(max=128)])
    option_d = StringField('Option D', validators=[DataRequired(), Length(max=128)])
    correct_answer = SelectField('Correct Answer', choices=[('A', 'A'), ('B', 'B'), ('C', 'C'), ('D', 'D')], validators=[DataRequired()])
    points = IntegerField('Points', validators=[DataRequired(), NumberRange(min=1)])
    image = SelectField('Image', validators=[Optional()], choices=[])
    explanation = TextAreaField('Explanation', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Save Question')

    def __init__(self, *args, **kwargs):
        super(QuestionForm, self).__init__(*args, **kwargs)
        self.image.choices = self.get_image_choices()

    def get_image_choices(self):
        image_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'questions')
        image_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        image_files.sort()  # Sort the image files alphabetically
        return [('', 'Select an image')] + [(f, f) for f in image_files]
    
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

class CourseForm(FlaskForm):
    name = StringField('Course Name', validators=[DataRequired(), Length(max=128)])
    description = TextAreaField('Description', validators=[Optional()])
    file_attachment = SelectField('File Attachment', validators=[Optional()], choices=[])
    image = SelectField('Course Image', validators=[Optional()], choices=[])
    tags = StringField('Tags', validators=[Optional(), Length(max=256)])
    purchase_url = URLField('Purchase URL', validators=[Optional(), URL(message='Please enter a valid URL.')])
    submit = SubmitField('Save Course')

    def __init__(self, *args, **kwargs):
        super(CourseForm, self).__init__(*args, **kwargs)
        self.file_attachment.choices = self.get_file_choices()
        self.image.choices = self.get_image_choices()

    def get_file_choices(self):
        file_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'studyfiles')
        allowed_extensions = current_app.config['ALLOWED_EXTENSIONS']
        files = [f for f in os.listdir(file_folder) if f.lower().split('.')[-1] in allowed_extensions]
        files.sort()  # Sort the files alphabetically
        return [('', 'Select a file')] + [(f, f) for f in files]

    def get_image_choices(self):
        image_folder = os.path.join(current_app.config['UPLOAD_FOLDER'], 'images', 'courses')
        image_files = [f for f in os.listdir(image_folder) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        image_files.sort()  # Sort the image files alphabetically
        return [('', 'Select an image')] + [(f, f) for f in image_files]