# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SubmitField
from wtforms.validators import DataRequired, URL, EqualTo, ValidationError

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class LinkForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired(), URL()])
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    tags = StringField('Tags (separated by spaces)')
    private = BooleanField('Private')
    read_later = BooleanField('Read Later')
    archive = BooleanField('Archive Page')
    submit = SubmitField('Submit')

class EditLinkForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    tags = StringField('Tags (separated by spaces)')
    private = BooleanField('Private')
    read_later = BooleanField('Read Later')
    submit = SubmitField('Update')

class PreferencesForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        EqualTo('confirm_new_password', message='Passwords must match')
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Update')

    def __init__(self, user, *args, **kwargs):
        super(PreferencesForm, self).__init__(*args, **kwargs)
        self.user = user

    def validate_current_password(self, field):
        if not self.user.check_password(field.data):
            raise ValidationError('Current password is incorrect.')
