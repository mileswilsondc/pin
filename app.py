# app.py
from flask import Flask, render_template, redirect, url_for, request, flash, abort, g
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from models import db, User, Link, Tag
from forms import RegistrationForm, LoginForm, LinkForm, EditLinkForm, PreferencesForm
from archive import archive_page
import pytz
from datetime import datetime
import time
from functools import wraps  # For admin_required decorator
from functools import wraps
from flask_wtf import CSRFProtect
from urllib.parse import unquote

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pinboard.db'
db.init_app(app)

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Home page
@app.route('/')
def index():
    if current_user.is_authenticated:
        links = Link.query.filter_by(user_id=current_user.id).order_by(Link.id.desc()).all()
    else:
        links = Link.query.filter_by(private=False).order_by(Link.id.desc()).all()
    return render_template('index.html', links=links)

# User registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_count = User.query.count()
        is_admin = False
        if user_count == 0:
            is_admin = True  # First user is admin
        user = User(username=form.username.data, admin=is_admin)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            #flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

# User logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Submit a new link
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_link():
    form = LinkForm()

    if request.method == 'GET':
        # Pre-fill form fields from query parameters if available
        url = request.args.get('url')
        title = request.args.get('title')
        tags = request.args.get('tags')
        read_later = request.args.get('read_later')
        private_param = request.args.get('private')

        if url:
            form.url.data = unquote(url)
        if title:
            form.title.data = unquote(title)
        if tags:
            form.tags.data = unquote(tags)
        if read_later and read_later.lower() == 'true':
            form.read_later.data = True
        
        if private_param is not None:
            form.private.data = private_param.lower() == 'true'
        else:
            # Set 'private' based on user preference
            form.private.data = current_user.add_bookmarks_private_by_default

    if form.validate_on_submit():
        # Create a new Link instance
        link = Link(
            url=form.url.data,
            title=form.title.data,
            description=form.description.data,
            extract=form.extract.data,
            private=form.private.data,
            read_later=form.read_later.data,
            user_id=current_user.id
        )
        db.session.add(link)
        db.session.flush()  # Flush to assign an ID to the link

        # Process tags
        tag_names = form.tags.data.split()
        for name in tag_names:
            name = name.strip().lower()  # Normalize tag names
            if not name:
                continue  # Skip empty tags
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)
            link.tags.append(tag)

        db.session.commit()
        flash('Link submitted successfully.')
        return redirect(url_for('index'))
    
    return render_template('submit.html', form=form)

# User's own links
@app.route('/me')
@login_required
def my_links():
    return redirect(url_for('user_links', username=current_user.username))

@app.route('/user/<username>')
def user_links(username):
    user = User.query.filter_by(username=username).first_or_404()
    is_owner = current_user.is_authenticated and current_user.username == username

    if is_owner:
        links = Link.query.filter_by(user_id=user.id).order_by(Link.id.desc()).all()
    else:
        links = Link.query.filter_by(user_id=user.id, private=False).order_by(Link.id.desc()).all()

    # Compute tag counts
    tag_counts = {}
    for link in links:
        for tag in link.tags:
            # Skip hidden tags for other users
            if tag.name.startswith('.') and not is_owner:
                continue
            tag_counts[tag.name] = tag_counts.get(tag.name, 0) + 1

    # Sort and limit to top x tags
    top_x = 100
    sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:top_x]
    # Now sort alphabetically
    sorted_tags.sort(key=lambda x: x[0])

    # Compute font sizes
    counts = [count for name, count in sorted_tags]
    if counts:
        max_count = max(counts)
        min_count = min(counts)
    else:
        max_count = min_count = 1  # Avoid division by zero

    def map_count_to_size(count, min_count, max_count, min_size=10, max_size=30):
        if max_count == min_count:
            return int((max_size + min_size) / 2)
        else:
            size = min_size + (count - min_count) * (max_size - min_size) / (max_count - min_count)
            return int(round(size))

    tags_with_sizes = []
    for name, count in sorted_tags:
        size = map_count_to_size(count, min_count, max_count)
        tags_with_sizes.append({'name': name, 'count': count, 'size': size})

    return render_template('user_links.html', links=links, user=user, tags=tags_with_sizes)

# Browse by tag
@app.route('/tag/<tag_name>')
def tag_links(tag_name):
    tag = Tag.query.filter_by(name=tag_name).first_or_404()
    if current_user.is_authenticated:
        links = tag.links.order_by(Link.id.desc()).all()
    else:
        links = tag.links.filter_by(private=False).order_by(Link.id.desc()).all()
    return render_template('tag_links.html', links=links, tag=tag)

# Unread links
@app.route('/read-later')
@login_required
def unread_links():
    links = Link.query.filter_by(user_id=current_user.id, read_later=True).order_by(Link.id.desc()).all()
    return render_template('unread_links.html', links=links)

# Edit a link
@app.route('/edit/<int:link_id>', methods=['GET', 'POST'])
@login_required
def edit_link(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id:
        abort(403)  # Forbidden
    form = EditLinkForm(obj=link)
    if form.validate_on_submit():
        link.title = form.title.data
        link.description = form.description.data
        link.extract = form.extract.data  # Update the extract
        link.private = form.private.data
        link.read_later = form.read_later.data

        # Handle tags
        link.tags.clear()
        tag_list = form.tags.data.split()
        for tag_name in tag_list:
            tag_name = tag_name.strip().lower()
            if not tag_name:
                continue
            tag = Tag.query.filter_by(name=tag_name).first()
            if not tag:
                tag = Tag(name=tag_name)
                db.session.add(tag)
            link.tags.append(tag)

        db.session.commit()
        flash('Link updated successfully.')
        return redirect(url_for('my_links'))
    else:
        form.tags.data = ' '.join([tag.name for tag in link.tags])
        form.extract.data = link.extract
    return render_template('edit_link.html', form=form, link=link)

@app.route('/extract/<int:link_id>')
@login_required
def view_extract(link_id):
    link = Link.query.get_or_404(link_id)
    # Check permissions: if link is private and not owned by the current user, abort
    if link.private and link.user_id != current_user.id:
        abort(403)
    if not link.extract:
        flash('No extract available for this link.')
        return redirect(url_for('index'))
    return render_template('extract.html', link=link)

# Mark link as read
@app.route('/read/<int:link_id>')
@login_required
def mark_as_read(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id:
        abort(403)
    link.read_later = False
    db.session.commit()
    flash('Link marked as read.')
    return redirect(request.referrer or url_for('my_links'))

# Delete a link
@app.route('/delete/<int:link_id>', methods=['POST'])
@login_required
def delete_link(link_id):
    link = Link.query.get_or_404(link_id)
    if link.user_id != current_user.id:
        abort(403)
    db.session.delete(link)
    db.session.commit()
    flash('Link deleted successfully.')
    return redirect(request.referrer or url_for('my_links'))

# User Preferences
@app.route('/preferences', methods=['GET', 'POST'])
@login_required
def preferences():
    form = PreferencesForm(user=current_user)
    if form.validate_on_submit():
        # Update password only if a new password is provided
        if form.new_password.data:
            if not form.current_password.data:
                flash('Current password is required to change your password.', 'error')
                return render_template('preferences.html', form=form)
            if not current_user.check_password(form.current_password.data):
                flash('Current password is incorrect.', 'error')
                return render_template('preferences.html', form=form)
            current_user.set_password(form.new_password.data)
            flash('Your password has been updated.', 'success')
        
        # Update other preferences
        current_user.language = form.language.data
        current_user.timezone = form.timezone.data

        current_user.tag_autocompletion = form.tag_autocompletion.data
        current_user.sort_tags_by_frequency = form.sort_tags_by_frequency.data
        current_user.use_return_key_for_autocomplete = form.use_return_key_for_autocomplete.data
        current_user.mark_toread_as_read_on_click = form.mark_toread_as_read_on_click.data
        current_user.open_links_in_new_window = form.open_links_in_new_window.data
        current_user.enable_keyboard_shortcuts = form.enable_keyboard_shortcuts.data
        current_user.subscribe_to_tags = form.subscribe_to_tags.data
        current_user.part_of_fandom = form.part_of_fandom.data
        current_user.enable_tag_bundles = form.enable_tag_bundles.data
        current_user.always_show_tags_alphabetical = form.always_show_tags_alphabetical.data
        current_user.display_url_under_title = form.display_url_under_title.data
        current_user.show_global_bookmark_counts = form.show_global_bookmark_counts.data
        current_user.show_exact_datetime_on_bookmarks = form.show_exact_datetime_on_bookmarks.data
        current_user.add_bookmarks_private_by_default = form.add_bookmarks_private_by_default.data
        current_user.enable_public_profile = form.enable_public_profile.data
        current_user.enable_privacy_mode = form.enable_privacy_mode.data

        db.session.commit()
        flash('Your preferences have been updated.', 'success')
        return redirect(url_for('index'))
    return render_template('preferences.html', form=form)


# Admin Page
@app.route('/admin')
@admin_required
def admin_page():
    users = User.query.all()
    return render_template('admin.html', users=users)

def format_relative_time(dt):
    now = datetime.utcnow()
    diff = now - dt

    seconds = diff.total_seconds()
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24

    if seconds < 60:
        return "just now"
    elif minutes < 60:
        mins = int(minutes)
        return f"{mins} minute{'s' if mins != 1 else ''} ago"
    elif hours < 24:
        hrs = int(hours)
        return f"{hrs} hour{'s' if hrs != 1 else ''} ago"
    elif days < 2:
        return "yesterday"
    elif days < 7:
        dys = int(days)
        return f"{dys} day{'s' if dys != 1 else ''} ago"
    else:
        return dt.strftime("%B %Y")
app.jinja_env.filters['format_relative_time'] = format_relative_time

@app.route('/faq')
@login_required
def faq():
    return render_template('faq.html')

@app.before_request
def start_timer():
    g.start_time = time.time()

@app.context_processor
def inject_render_time():
    render_time = None
    if hasattr(g, 'start_time'):
        render_time = f"{(time.time() - g.start_time) * 1000:.2f} ms"
    return dict(render_time=render_time)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def format_datetime(dt, timezone_str='Etc/UTC'):
    try:
        timezone = pytz.timezone(timezone_str)
    except Exception:
        timezone = pytz.utc
    dt = dt.replace(tzinfo=pytz.utc).astimezone(timezone)
    return dt.strftime('%Y-%m-%d %H:%M:%S %Z')

app.jinja_env.filters['format_datetime'] = format_datetime

if __name__ == '__main__':
    app.run(debug=True)
