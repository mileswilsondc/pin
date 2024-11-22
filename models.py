# models.py
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

link_tags = db.Table('link_tags',
    db.Column('link_id', db.Integer, db.ForeignKey('link.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    admin = db.Column(db.Boolean, default=False)  # Existing admin flag
    links = db.relationship('Link', backref='user', lazy='dynamic')
    
    language = db.Column(db.String(32), default='en')
    timezone = db.Column(db.String(64), default='UTC')
    
    tag_autocompletion = db.Column(db.Boolean, default=True)
    sort_tags_by_frequency = db.Column(db.Boolean, default=False)
    use_return_key_for_autocomplete = db.Column(db.Boolean, default=True)
    mark_toread_as_read_on_click = db.Column(db.Boolean, default=False)
    open_links_in_new_window = db.Column(db.Boolean, default=False)
    enable_keyboard_shortcuts = db.Column(db.Boolean, default=False)
    subscribe_to_tags = db.Column(db.Boolean, default=False)
    part_of_fandom = db.Column(db.Boolean, default=False)
    enable_tag_bundles = db.Column(db.Boolean, default=False)
    always_show_tags_alphabetical = db.Column(db.Boolean, default=False)
    display_url_under_title = db.Column(db.Boolean, default=False)
    show_global_bookmark_counts = db.Column(db.Boolean, default=False)
    show_exact_datetime_on_bookmarks = db.Column(db.Boolean, default=False)
    add_bookmarks_private_by_default = db.Column(db.Boolean, default=False)
    enable_public_profile = db.Column(db.Boolean, default=False)
    enable_privacy_mode = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text)
    extract = db.Column(db.Text)
    private = db.Column(db.Boolean, default=False)
    read_later = db.Column(db.Boolean, default=False)
    archive_url = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tags = db.relationship('Tag', secondary=link_tags, backref=db.backref('links', lazy='dynamic'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
