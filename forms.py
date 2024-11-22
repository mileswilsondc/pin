# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SubmitField, SelectField, HiddenField
from wtforms.validators import DataRequired, URL, EqualTo, ValidationError, Optional
from models import User

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
    extract = TextAreaField('Extract')
    tags = StringField('Tags (separated by spaces)')
    private = BooleanField('Private')
    read_later = BooleanField('Read Later')
    archive = BooleanField('Archive Page')
    submit = SubmitField('Submit')

class EditLinkForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    extract = TextAreaField('Extract')
    tags = StringField('Tags (separated by spaces)')
    private = BooleanField('Private')
    read_later = BooleanField('Read Later')
    submit = SubmitField('Update')

class PreferencesForm(FlaskForm):
    # Password Fields
    current_password = PasswordField('Current Password', validators=[Optional()])
    new_password = PasswordField('New Password', validators=[
        Optional(),
        EqualTo('confirm_new_password', message='Passwords must match')
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[Optional()])
    
    language = SelectField('Language', choices=[
        ('en', 'English'),
        ('es', 'Spanish / Español'),
        ('fr', 'French / Français'),
        ('de', 'German / Deutsch'),
        ('cn', 'Chinese / 中文'),
        ('jp', 'Japanese / 日本語'),
    ], default='en')
    
    timezone = SelectField('Timezone', choices=[
        ('Etc/UTC', 'UTC (default)'),
        ('America/Anchorage', '-9:00 : Alaska'),
        ('America/Ensenada', '-8:00 : Tijuana, Baja California'),
        ('America/Los_Angeles', '-8:00 : Pacific Time'),
        ('America/Denver', '-7:00 : Mountain Time'),
        ('America/Chihuahua', '-7:00 : Chihuahua, La Paz'),
        ('America/Dawson_Creek', '-7:00 : Arizona'),
        ('America/Belize', '-6:00 : Saskatchewan, Central America'),
        ('America/Cancun', '-6:00 : Guadalajara, Mexico City'),
        ('America/Chicago', '-6:00 : Central Time'),
        ('America/New_York', '-5:00 : Eastern Time'),
        ('America/Havana', '-5:00 : Cuba'),
        ('America/Bogota', '-5:00 : Bogota, Lima, Quito'),
        ('America/Caracas', '-4:30 : Caracas'),
        ('America/Santiago', '-4:00 : Santiago'),
        ('America/La_Paz', '-4:00 : La Paz'),
        ('America/Campo_Grande', '-4:00 : Brazil'),
        ('America/Goose_Bay', '-4:00 : Atlantic Time'),
        ('America/St_Johns', '-3:30 : Newfoundland'),
        ('America/Montevideo', '-3:00 : Montevideo'),
        ('America/Argentina/Buenos_Aires', '-3:00 : Buenos Aires'),
        ('America/Sao_Paulo', '-3:00 : Brasilia'),
        ('Europe/London', '+0:00 : London, Reykjavik, GMT'),
        ('Europe/Amsterdam', '+1:00 : Amsterdam, Berlin, Rome'),
        ('Europe/Belgrade', '+1:00 : Belgrade, Budapest, Prague'),
        ('Asia/Beirut', '+2:00 : Beirut'),
        ('Africa/Cairo', '+2:00 : Cairo'),
        ('Africa/Blantyre', '+2:00 : Harare, Pretoria'),
        ('Asia/Jerusalem', '+2:00 : Jerusalem'),
        ('Europe/Moscow', '+3:00 : Moscow, St. Petersburg'),
        ('Africa/Addis_Ababa', '+3:00 : Nairobi'),
        ('Asia/Tehran', '+3:30 : Tehran'),
        ('Asia/Dubai', '+4:00 : Abu Dhabi, Muscat'),
        ('Asia/Yerevan', '+4:00 : Yerevan'),
        ('Asia/Kabul', '+4:30 : Kabul'),
        ('Asia/Yekaterinburg', '+5:00 : Ekaterinburg'),
        ('Asia/Tashkent', '+5:00 : Tashkent'),
        ('Asia/Kolkata', '+5:30 : Chennai, Mumbai, New Delhi'),
        ('Asia/Katmandu', '+5:45 : Kathmandu'),
        ('Asia/Dhaka', '+6:00 : Astana, Dhaka'),
        ('Asia/Novosibirsk', '+6:00 : Novosibirsk'),
        ('Asia/Rangoon', '+6:30 : Yangon (Rangoon)'),
        ('Asia/Bangkok', '+7:00 : Bangkok, Hanoi, Jakarta'),
        ('Asia/Krasnoyarsk', '+7:00 : Krasnoyarsk'),
        ('Asia/Hong_Kong', '+8:00 : Beijing, Hong Kong'),
        ('Asia/Irkutsk', '+8:00 : Irkutsk, Ulaan Bataar'),
        ('Australia/Perth', '+8:00 : Perth'),
        ('Asia/Tokyo', '+9:00 : Osaka, Sapporo, Tokyo'),
        ('Asia/Seoul', '+9:00 : Seoul'),
        ('Australia/Adelaide', '+9:30 : Adelaide'),
        ('Australia/Darwin', '+9:30 : Darwin'),
        ('Australia/Brisbane', '+10:00 : Brisbane'),
        ('Australia/Hobart', '+10:00 : Hobart'),
        ('Asia/Vladivostok', '+10:00 : Vladivostok'),
        ('Asia/Magadan', '+11:00 : Magadan'),
        ('Pacific/Auckland', '+12:00 : Auckland, Wellington'),
        ('Etc/GMT-12', '+12:00 : Fiji, Kamchatka, Marshall Is.'),
        ('Pacific/Midway', '-11:00 : Midway Island, Samoa'),
        ('America/Adak', '-10:00 : Hawaii, Aleutians'),
    ], default='Etc/UTC')

    # Checkbox Preferences
    tag_autocompletion = BooleanField('Enable Tag Autocompletion')
    sort_tags_by_frequency = BooleanField('Sort Tags in Autocomplete by Frequency')
    use_return_key_for_autocomplete = BooleanField('Use Return Key for Autocomplete')
    mark_toread_as_read_on_click = BooleanField("Clicking 'ToRead' Items Marks Them as Read")
    open_links_in_new_window = BooleanField('Open Links in New Window')
    enable_keyboard_shortcuts = BooleanField('Enable Keyboard Shortcuts')
    subscribe_to_tags = BooleanField('Allow Me to Subscribe to Tags')
    part_of_fandom = BooleanField('I am Part of a Fandom')
    enable_tag_bundles = BooleanField('Enable Tag Bundles')
    always_show_tags_alphabetical = BooleanField('Always Show Tags for Bookmarks in Alphabetical Order')
    display_url_under_title = BooleanField('Display URL Under Each Bookmark Title')
    show_global_bookmark_counts = BooleanField('Show Global Bookmark Counts')
    show_exact_datetime_on_bookmarks = BooleanField('Show Exact Date and Time on Bookmarks')
    add_bookmarks_private_by_default = BooleanField('Add Bookmarks as Private by Default')
    enable_public_profile = BooleanField('Enable Public Profile')
    enable_privacy_mode = BooleanField('Enable Privacy Mode')

    submit = SubmitField('Update')

    def __init__(self, user, *args, **kwargs):
        super(PreferencesForm, self).__init__(*args, **kwargs)
        self.user = user

        if not self.is_submitted():
            # Initialize form fields with user's current settings
            self.language.data = user.language
            self.timezone.data = user.timezone
            self.tag_autocompletion.data = user.tag_autocompletion
            self.sort_tags_by_frequency.data = user.sort_tags_by_frequency
            self.use_return_key_for_autocomplete.data = user.use_return_key_for_autocomplete
            self.mark_toread_as_read_on_click.data = user.mark_toread_as_read_on_click
            self.open_links_in_new_window.data = user.open_links_in_new_window
            self.enable_keyboard_shortcuts.data = user.enable_keyboard_shortcuts
            self.subscribe_to_tags.data = user.subscribe_to_tags
            self.part_of_fandom.data = user.part_of_fandom
            self.enable_tag_bundles.data = user.enable_tag_bundles
            self.always_show_tags_alphabetical.data = user.always_show_tags_alphabetical
            self.display_url_under_title.data = user.display_url_under_title
            self.show_global_bookmark_counts.data = user.show_global_bookmark_counts
            self.show_exact_datetime_on_bookmarks.data = user.show_exact_datetime_on_bookmarks
            self.add_bookmarks_private_by_default.data = user.add_bookmarks_private_by_default
            self.enable_public_profile.data = user.enable_public_profile
            self.enable_privacy_mode.data = user.enable_privacy_mode

    def validate_current_password(self, field):
        # Only validate if new_password is provided
        if self.new_password.data:
            if not field.data:
                raise ValidationError('Current password is required to change your password.')
            if not self.user.check_password(field.data):
                raise ValidationError('Current password is incorrect.')

class AdminRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    admin = BooleanField('Administrator')
    submit = SubmitField('Register New User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')

class AdminEditUserForm(FlaskForm):
    user_id = HiddenField('User ID')

    new_password = PasswordField('New Password', validators=[
        Optional(),
        EqualTo('confirm_new_password', message='Passwords must match.')
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[Optional()])

    language = SelectField('Language', choices=[
        ('en', 'English'),
        ('es', 'Spanish / Español'),
        ('fr', 'French / Français'),
        ('de', 'German / Deutsch'),
        ('cn', 'Chinese / 中文'),
        ('jp', 'Japanese / 日本語'),
    ], default='en')

    timezone = SelectField('Timezone', choices=[
        ('Etc/UTC', 'UTC (default)'),
        ('America/Anchorage', '-9:00 : Alaska'),
        ('America/Ensenada', '-8:00 : Tijuana, Baja California'),
        ('America/Los_Angeles', '-8:00 : Pacific Time'),
        ('America/Denver', '-7:00 : Mountain Time'),
        ('America/Chihuahua', '-7:00 : Chihuahua, La Paz'),
        ('America/Dawson_Creek', '-7:00 : Arizona'),
        ('America/Belize', '-6:00 : Saskatchewan, Central America'),
        ('America/Cancun', '-6:00 : Guadalajara, Mexico City'),
        ('America/Chicago', '-6:00 : Central Time'),
        ('America/New_York', '-5:00 : Eastern Time'),
        ('America/Havana', '-5:00 : Cuba'),
        ('America/Bogota', '-5:00 : Bogota, Lima, Quito'),
        ('America/Caracas', '-4:30 : Caracas'),
        ('America/Santiago', '-4:00 : Santiago'),
        ('America/La_Paz', '-4:00 : La Paz'),
        ('America/Campo_Grande', '-4:00 : Brazil'),
        ('America/Goose_Bay', '-4:00 : Atlantic Time'),
        ('America/St_Johns', '-3:30 : Newfoundland'),
        ('America/Montevideo', '-3:00 : Montevideo'),
        ('America/Argentina/Buenos_Aires', '-3:00 : Buenos Aires'),
        ('America/Sao_Paulo', '-3:00 : Brasilia'),
        ('Europe/London', '+0:00 : London, Reykjavik, GMT'),
        ('Europe/Amsterdam', '+1:00 : Amsterdam, Berlin, Rome'),
        ('Europe/Belgrade', '+1:00 : Belgrade, Budapest, Prague'),
        ('Asia/Beirut', '+2:00 : Beirut'),
        ('Africa/Cairo', '+2:00 : Cairo'),
        ('Africa/Blantyre', '+2:00 : Harare, Pretoria'),
        ('Asia/Jerusalem', '+2:00 : Jerusalem'),
        ('Europe/Moscow', '+3:00 : Moscow, St. Petersburg'),
        ('Africa/Addis_Ababa', '+3:00 : Nairobi'),
        ('Asia/Tehran', '+3:30 : Tehran'),
        ('Asia/Dubai', '+4:00 : Abu Dhabi, Muscat'),
        ('Asia/Yerevan', '+4:00 : Yerevan'),
        ('Asia/Kabul', '+4:30 : Kabul'),
        ('Asia/Yekaterinburg', '+5:00 : Ekaterinburg'),
        ('Asia/Tashkent', '+5:00 : Tashkent'),
        ('Asia/Kolkata', '+5:30 : Chennai, Mumbai, New Delhi'),
        ('Asia/Katmandu', '+5:45 : Kathmandu'),
        ('Asia/Dhaka', '+6:00 : Astana, Dhaka'),
        ('Asia/Novosibirsk', '+6:00 : Novosibirsk'),
        ('Asia/Rangoon', '+6:30 : Yangon (Rangoon)'),
        ('Asia/Bangkok', '+7:00 : Bangkok, Hanoi, Jakarta'),
        ('Asia/Krasnoyarsk', '+7:00 : Krasnoyarsk'),
        ('Asia/Hong_Kong', '+8:00 : Beijing, Hong Kong'),
        ('Asia/Irkutsk', '+8:00 : Irkutsk, Ulaan Bataar'),
        ('Australia/Perth', '+8:00 : Perth'),
        ('Asia/Tokyo', '+9:00 : Osaka, Sapporo, Tokyo'),
        ('Asia/Seoul', '+9:00 : Seoul'),
        ('Australia/Adelaide', '+9:30 : Adelaide'),
        ('Australia/Darwin', '+9:30 : Darwin'),
        ('Australia/Brisbane', '+10:00 : Brisbane'),
        ('Australia/Hobart', '+10:00 : Hobart'),
        ('Asia/Vladivostok', '+10:00 : Vladivostok'),
        ('Asia/Magadan', '+11:00 : Magadan'),
        ('Pacific/Auckland', '+12:00 : Auckland, Wellington'),
        ('Etc/GMT-12', '+12:00 : Fiji, Kamchatka, Marshall Is.'),
        ('Pacific/Midway', '-11:00 : Midway Island, Samoa'),
        ('America/Adak', '-10:00 : Hawaii, Aleutians'),
    ], default='Etc/UTC')

    # Checkbox Preferences
    tag_autocompletion = BooleanField('Enable Tag Autocompletion')
    sort_tags_by_frequency = BooleanField('Sort Tags in Autocomplete by Frequency')
    use_return_key_for_autocomplete = BooleanField('Use Return Key for Autocomplete')
    mark_toread_as_read_on_click = BooleanField("Clicking 'ToRead' Items Marks Them as Read")
    open_links_in_new_window = BooleanField('Open Links in New Window')
    enable_keyboard_shortcuts = BooleanField('Enable Keyboard Shortcuts')
    subscribe_to_tags = BooleanField('Allow Me to Subscribe to Tags')
    part_of_fandom = BooleanField('I am Part of a Fandom')
    enable_tag_bundles = BooleanField('Enable Tag Bundles')
    always_show_tags_alphabetical = BooleanField('Always Show Tags for Bookmarks in Alphabetical Order')
    display_url_under_title = BooleanField('Display URL Under Each Bookmark Title')
    show_global_bookmark_counts = BooleanField('Show Global Bookmark Counts')
    show_exact_datetime_on_bookmarks = BooleanField('Show Exact Date and Time on Bookmarks')
    add_bookmarks_private_by_default = BooleanField('Add Bookmarks as Private by Default')
    enable_public_profile = BooleanField('Enable Public Profile')
    enable_privacy_mode = BooleanField('Enable Privacy Mode')

    submit = SubmitField('Update')

    def __init__(self, user, *args, **kwargs):
        super(AdminEditUserForm, self).__init__(*args, **kwargs)
        self.user = user

        if not self.is_submitted():
            # Initialize form fields with user's current settings
            self.language.data = user.language
            self.timezone.data = user.timezone
            self.tag_autocompletion.data = user.tag_autocompletion
            self.sort_tags_by_frequency.data = user.sort_tags_by_frequency
            self.use_return_key_for_autocomplete.data = user.use_return_key_for_autocomplete
            self.mark_toread_as_read_on_click.data = user.mark_toread_as_read_on_click
            self.open_links_in_new_window.data = user.open_links_in_new_window
            self.enable_keyboard_shortcuts.data = user.enable_keyboard_shortcuts
            self.subscribe_to_tags.data = user.subscribe_to_tags
            self.part_of_fandom.data = user.part_of_fandom
            self.enable_tag_bundles.data = user.enable_tag_bundles
            self.always_show_tags_alphabetical.data = user.always_show_tags_alphabetical
            self.display_url_under_title.data = user.display_url_under_title
            self.show_global_bookmark_counts.data = user.show_global_bookmark_counts
            self.show_exact_datetime_on_bookmarks.data = user.show_exact_datetime_on_bookmarks
            self.add_bookmarks_private_by_default.data = user.add_bookmarks_private_by_default
            self.enable_public_profile.data = user.enable_public_profile
            self.enable_privacy_mode.data = user.enable_privacy_mode

    def validate_new_password(self, field):
        if field.data:
            if len(field.data) < 6:
                raise ValidationError('Password must be at least 6 characters long.')