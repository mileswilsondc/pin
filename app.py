# app.py (Modified index route with cursor-based pagination)
from flask import Flask, render_template, redirect, url_for, request, flash, abort, g, jsonify, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from models import db, User, Link, Tag, link_tags
from forms import (
    RegistrationForm, LoginForm, LinkForm, EditLinkForm,
    PreferencesForm, AdminEditUserForm, AdminRegistrationForm,
    ImportForm
)
from archive import archive_page
import pytz
from datetime import datetime, timedelta
import time
import json
import io
from functools import wraps
from flask_wtf import CSRFProtect
from urllib.parse import unquote
from sqlalchemy import func, desc
from sqlalchemy.orm import joinedload
from collections import defaultdict

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


def parse_filters(filters):
    """
    Parse filter path segments into a dictionary.
    Supports multiple 'tag' filters and other specific filters including 'paginate' and 'paginate_after'.
    """
    filter_parts = filters.split('/') if filters else []
    filter_dict = defaultdict(list)

    for part in filter_parts:
        if ':' in part:
            key, value = part.split(':', 1)
            key = key.lower()
            value = unquote(value)
            if key in ['tag', 'u', 'before', 'after', 'read_later', 'untagged', 'private', 'paginate', 'paginate_after']:
                filter_dict[key].append(value)
            else:
                flash(f'Unknown filter key: "{key}".', 'error')
                abort(400)
        else:
            flash(f'Invalid filter format: "{part}". Expected key:value.', 'error')
            abort(400)  # Bad Request

    return filter_dict

def apply_filters(query, filter_dict, exclude_keys=[]):
    """
    Apply filters from the filter_dict to the SQLAlchemy query.
    Allows excluding certain keys (e.g., 'paginate') from being applied.
    """
    for key, values in filter_dict.items():
        if key in exclude_keys:
            continue
        if key == 'u':
            username = values[0]  # Assuming single user filter
            user = User.query.filter_by(username=username).first()
            if not user:
                flash(f'User "{username}" not found.', 'error')
                abort(404)
            query = query.filter(Link.user_id == user.id)
        elif key == 'before':
            try:
                timestamp = int(values[0])  # Assuming single before filter
                dt_before = datetime.utcfromtimestamp(timestamp)
                query = query.filter(Link.created_at < dt_before)
            except ValueError:
                flash('Invalid "before" timestamp. It must be a valid Unix timestamp.', 'error')
                abort(400)
        elif key == 'after':
            try:
                timestamp = int(values[0])  # Assuming single after filter
                dt_after = datetime.utcfromtimestamp(timestamp)
                query = query.filter(Link.created_at > dt_after)
            except ValueError:
                flash('Invalid "after" timestamp. It must be a valid Unix timestamp.', 'error')
                abort(400)
        elif key == 'tag':
            tag_names = [t.lower() for t in values]
            tags = Tag.query.filter(Tag.name.in_(tag_names)).all()
            if not tags:
                query = query.filter(False)  # No results
            else:
                for tag in tags:
                    query = query.filter(Link.tags.contains(tag))
        elif key == 'untagged':
            for value in values:
                if value.lower() == 'true':
                    query = query.filter(~Link.tags.any())
                elif value.lower() == 'false':
                    pass  # No filtering needed
                else:
                    flash('Invalid value for "untagged" filter. Use true or false.', 'error')
                    abort(400)
        elif key == 'read_later':
            if not current_user.is_authenticated:
                flash('You need to be logged in to filter by read_later.', 'error')
                abort(403)
            for value in values:
                if value.lower() in ['true', '1', 'yes']:
                    query = query.filter(Link.read_later == True)
                elif value.lower() in ['false', '0', 'no']:
                    query = query.filter(Link.read_later == False)
                else:
                    flash('Invalid value for "read_later" filter. Use true or false.', 'error')
                    abort(400)
            # Ensure we only show the current user's read_later links
            query = query.filter(Link.user_id == current_user.id)
        elif key == 'private':
            for value in values:
                if value.lower() == 'true':
                    query = query.filter(Link.private == True)
                elif value.lower() == 'false':
                    query = query.filter(Link.private == False)
                else:
                    flash('Invalid value for "private" filter. Use true or false.', 'error')
                    abort(400)
        elif key == 'paginate':
            try:
                paginate_timestamp = int(values[0])
                if paginate_timestamp < 0:
                    raise ValueError
                paginate_datetime = datetime.utcfromtimestamp(paginate_timestamp)
                query = query.filter(Link.created_at < paginate_datetime)
            except ValueError:
                flash('Invalid "paginate" value. It must be a positive integer UNIX timestamp.', 'error')
                abort(400)
        elif key == 'paginate_after':
            try:
                paginate_after_timestamp = int(values[0])
                if paginate_after_timestamp < 0:
                    raise ValueError
                paginate_after_datetime = datetime.utcfromtimestamp(paginate_after_timestamp)
                query = query.filter(Link.created_at > paginate_after_datetime)
            except ValueError:
                flash('Invalid "paginate_after" value. It must be a positive integer UNIX timestamp.', 'error')
                abort(400)
        # Add more filters as needed

    # Order the results (newest first)
    query = query.order_by(Link.created_at.desc())

    # Eager load tags to optimize database queries
    query = query.options(joinedload(Link.tags))

    return query

# Home page
@app.route('/', defaults={'filters': ''})
@app.route('/<path:filters>')
def index(filters):
    """
    Display bookmarks with optional filtering based on URL path parameters.
    Example URLs:
      - /u:miles/paginate:1732390462/tag:macos
      - /u:miles/paginate_after:1732390462/tag:macos
    """
    filter_dict = parse_filters(filters)
    
    # Base query with applied filters except 'paginate' and 'paginate_after'
    base_query = Link.query
    base_query = apply_filters(base_query, filter_dict, exclude_keys=['paginate', 'paginate_after'])

    # Calculate total number of matching links (for result count and tag cloud)
    result_count = base_query.count()

    # Compute tag counts for tag cloud based on total query
    tag_counts = defaultdict(int)
    total_links = base_query.options(joinedload(Link.tags)).all()
    # Get active tags from filters
    active_tags = filter_dict.get('tag', [])

    for link in total_links:
        for tag in link.tags:
            # Skip tags that are in the active filters
            if tag.name in active_tags:
                continue
            if tag.name.startswith('.'):
                # Include private tags only if the link belongs to the current user
                if current_user.is_authenticated and link.user_id == current_user.id:
                    tag_counts[tag.name] += 1
            else:
                tag_counts[tag.name] += 1

    # Retrieve 'floor' from query parameters, default to 1
    floor = request.args.get('floor', default=1, type=int)
    if floor < 1:
        flash('Floor must be a positive integer.', 'error')
        abort(400)

    # Filter tags based on 'floor'
    filtered_tag_counts = {name: count for name, count in tag_counts.items() if count >= floor}

    # Sort tags by frequency and limit to top 100
    sorted_tags = sorted(filtered_tag_counts.items(), key=lambda x: x[1], reverse=True)[:100]
    # Sort alphabetically
    sorted_tags.sort(key=lambda x: x[0])

    # Determine min and max counts for font size scaling
    counts = [count for name, count in sorted_tags]
    if counts:
        max_count = max(counts)
        min_count = min(counts)
    else:
        max_count = min_count = 1  # Avoid division by zero

    # Function to map count to font size
    def map_count_to_size(count, min_count, max_count, min_size=10, max_size=30):
        if max_count == min_count:
            return int((max_size + min_size) / 2)
        else:
            size = min_size + (count - min_count) * (max_size - min_size) / (max_count - min_count)
            return int(round(size))

    # Create list of tags with computed sizes
    tags_with_sizes = [
        {'name': name, 'count': count, 'size': map_count_to_size(count, min_count, max_count)}
        for name, count in sorted_tags
    ]

    # Pagination parameters
    PAGE_SIZE = 12

    # Calculate filters_str
    filters_str = '/'.join([f"{key}:{value}" for key, values in filter_dict.items() for value in values])

    # Define the helper function before its usage
    def generate_paginate_url(filters, key, timestamp):
        """
        Generate a new filter path with updated 'paginate' or 'paginate_after' parameter.
        Preserves existing filters.
        """
        new_filter_dict = defaultdict(list, filters)
        new_filter_dict[key] = [str(timestamp)]
        # Remove the opposite pagination filter to avoid conflicts
        if key == 'paginate':
            if 'paginate_after' in new_filter_dict:
                del new_filter_dict['paginate_after']
        elif key == 'paginate_after':
            if 'paginate' in new_filter_dict:
                del new_filter_dict['paginate']
        parts = []
        for k, values in new_filter_dict.items():
            for v in values:
                parts.append(f"{k}:{v}")
        new_filters = '/'.join(parts)
        return url_for('index', filters=new_filters, floor=floor)

    # Determine current pagination state
    paginate = filter_dict.get('paginate', [None])[0]
    paginate_after = filter_dict.get('paginate_after', [None])[0]

    # Apply pagination filters
    paginated_query = apply_filters(Link.query, filter_dict, exclude_keys=[])

    # Fetch links based on 'paginate' and 'paginate_after'
    links = paginated_query.order_by(Link.created_at.desc()).limit(PAGE_SIZE).all()

    # Determine if there are more links for pagination
    has_next = False
    has_prev = False
    prev_url = None
    next_url = None

    if paginate:
        # "Later" link exists if we fetched PAGE_SIZE links
        if len(links) == PAGE_SIZE:
            has_next = True
            last_link = links[-1]
            next_paginate = int(last_link.created_at.timestamp())
            next_url = generate_paginate_url(filter_dict, 'paginate', next_paginate)
        # "Earlier" link exists if there is a paginate timestamp
        if paginate:
            has_prev = True
            first_link = links[0] if links else None
            if first_link:
                prev_paginate_after = int(first_link.created_at.timestamp())
                prev_url = generate_paginate_url(filter_dict, 'paginate_after', prev_paginate_after)
    elif paginate_after:
        # "Earlier" link exists if we have a paginate_after filter
        if len(links) > 0:
            has_prev = True
            first_link = links[0]
            prev_paginate_after = int(first_link.created_at.timestamp())
            prev_url = generate_paginate_url(filter_dict, 'paginate_after', prev_paginate_after)
        # "Later" link exists if we fetched PAGE_SIZE links
        if len(links) == PAGE_SIZE:
            has_next = True
            last_link = links[-1]
            next_paginate = int(last_link.created_at.timestamp())
            next_url = generate_paginate_url(filter_dict, 'paginate', next_paginate)
    else:
        # Initial page, check if there's a next page
        if len(links) == PAGE_SIZE:
            has_next = True
            last_link = links[-1]
            next_paginate = int(last_link.created_at.timestamp())
            next_url = generate_paginate_url(filter_dict, 'paginate', next_paginate)

    # Retrieve 'username' filter if present
    username = filter_dict.get('u', [None])[0]

    # Determine additional filter options based on total filtered links
    has_private = any(link.private for link in total_links)
    has_public = any(not link.private for link in total_links)
    has_unread = any(link.read_later for link in total_links)
    has_untagged = any(len(link.tags) == 0 for link in total_links)

    # Helper function to generate updated filter path for additional filters
    def generate_filter_path(filters, key, value):
        """
        Generate a new filter path with an updated 'key' filter.
        Preserves existing filters.
        """
        new_filter_dict = defaultdict(list, filters)
        new_filter_dict[key] = [str(value)]
        if key == 'paginate':
            if 'paginate_after' in new_filter_dict:
                del new_filter_dict['paginate_after']
        elif key == 'paginate_after':
            if 'paginate' in new_filter_dict:
                del new_filter_dict['paginate']
        parts = []
        for k, vals in new_filter_dict.items():
            for v in vals:
                parts.append(f"{k}:{v}")
        new_filters = '/'.join(parts)
        return url_for('index', filters=new_filters, floor=floor)

    # Calculate counts for each filter category
    public_count = base_query.filter_by(private=False).count()
    private_count = base_query.filter_by(private=True).count()
    unread_count = base_query.filter_by(read_later=True).count()
    untagged_count = base_query.filter(~Link.tags.any()).count()

    # Initialize filter_options with counts
    filter_options = []

    if private_count > 0 and public_count > 0:
        # Generate URL for 'public' filter
        new_filters_public = generate_filter_path(filter_dict, 'private', 'false')
        url_public = new_filters_public
        filter_options.append(('public', url_public, public_count))

        # Generate URL for 'private' filter
        new_filters_private = generate_filter_path(filter_dict, 'private', 'true')
        url_private = new_filters_private
        filter_options.append(('private', url_private, private_count))
    
    if unread_count > 0:
        new_filters_unread = generate_filter_path(filter_dict, 'read_later', 'true')
        url_unread = new_filters_unread
        filter_options.append(('unread', url_unread, unread_count))
    
    if untagged_count > 0:
        new_filters_untagged = generate_filter_path(filter_dict, 'untagged', 'true')
        url_untagged = new_filters_untagged
        filter_options.append(('untagged', url_untagged, untagged_count))

    return render_template(
        'filter_links.html',
        links=links,
        filters=filter_dict,
        filters_str=filters_str,           # Pass filters_str here
        tags=tags_with_sizes,              # Tag cloud data
        username=username,                 # Username filter if applied
        result_count=result_count,         # Number of results
        floor=floor,                       # Current floor value
        filter_options=filter_options,     # Additional filter options with counts
        has_prev=has_prev,
        has_next=has_next,
        prev_url=prev_url,
        next_url=next_url
    )

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

@app.route('/dmca', methods=['GET', 'POST'])
def dmca():
    return render_template('dmca.html')

def parse_tag_input(tag_input):
    """
    Parse the tag input string into a list of clean, lowercase tag names.
    """
    if not tag_input:
        return []
    # Split by comma, strip whitespace, and convert to lowercase
    return [tag.strip().lower() for tag in tag_input.split(',') if tag.strip()]

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
        tag_input = form.tags.data
        tag_names = parse_tag_input(tag_input)
        for name in tag_names:
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)
            link.tags.append(tag)

        db.session.commit()
        #flash('Link submitted successfully.')
        return redirect(url_for('index'))
    
    return render_template('submit.html', form=form)

# User's own links
@app.route('/me')
@login_required
def my_links():
    filters = f"u:{current_user.username}"
    return redirect(url_for('index', filters=filters))

# Unread links
@app.route('/read-later')
@login_required
def read_later_redirect():
    """
    Redirect /read-later to the main index with read_later filter.
    """
    filters = 'read_later:true'
    return redirect(url_for('index', filters=filters))

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
        tag_input = form.tags.data
        tag_names = parse_tag_input(tag_input)
        for name in tag_names:
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)
            link.tags.append(tag)

        db.session.commit()
        flash('Link updated successfully.')
        return redirect(url_for('my_links'))
    else:
        form.tags.data = ', '.join([tag.name for tag in link.tags])
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

        email = form.email.data
        full_name = form.full_name.data

        if email != current_user.email:
            if email and User.query.filter_by(email=email).first():
                flash('Email already in use. Please choose a different one.', 'error')
                return render_template('preferences.html', form=form)
            current_user.email = email

        current_user.full_name = full_name

        db.session.commit()
        flash('Your preferences have been updated.', 'success')
        return redirect(url_for('index'))
    return render_template('preferences.html', form=form)

# Admin Page
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_page():
    users = User.query.all()
    recent_links = Link.query.order_by(Link.created_at.desc()).limit(10).all()
    edit_forms = {}
    registration_form = AdminRegistrationForm(prefix='register')

    if request.method == 'POST':
        # Determine which form was submitted based on the form prefix
        if 'register-' in request.form.get('csrf_token', ''):
            # Handle new user registration
            if registration_form.validate_on_submit():
                new_user = User(
                    username=registration_form.username.data,
                    email=registration_form.email.data,  # Set email if provided
                    full_name=registration_form.full_name.data,  # Set full name if provided
                    admin=registration_form.admin.data,
                    language='en',  # Default preferences; adjust as needed
                    timezone='Etc/UTC'
                )
                new_user.set_password(registration_form.password.data)
                db.session.add(new_user)
                db.session.commit()
                flash(f'User "{new_user.username}" has been successfully registered.', 'success')
                return redirect(url_for('admin_page'))
            else:
                flash('Error registering new user. Please check the form for errors.', 'error')
        else:
            # Handle user edit forms
            # Iterate through all users to check which form was submitted
            for user in users:
                form_prefix = f'user_{user.id}'
                form = AdminEditUserForm(user=user, prefix=form_prefix, obj=user)  # Pass 'user' here
                if form.validate_on_submit():
                    # Update password if provided
                    if form.new_password.data:
                        user.set_password(form.new_password.data)
                        flash(f'Password updated for user "{user.username}".', 'success')

                    # Update email and full_name
                    if form.email.data != user.email:
                        if form.email.data and User.query.filter_by(email=form.email.data).first():
                            flash(f'Email "{form.email.data}" is already in use.', 'error')
                            return redirect(url_for('admin_page'))
                        user.email = form.email.data

                    user.full_name = form.full_name.data

                    # Update preferences
                    user.language = form.language.data
                    user.timezone = form.timezone.data
                    user.tag_autocompletion = form.tag_autocompletion.data
                    user.sort_tags_by_frequency = form.sort_tags_by_frequency.data
                    user.use_return_key_for_autocomplete = form.use_return_key_for_autocomplete.data
                    user.mark_toread_as_read_on_click = form.mark_toread_as_read_on_click.data
                    user.open_links_in_new_window = form.open_links_in_new_window.data
                    user.enable_keyboard_shortcuts = form.enable_keyboard_shortcuts.data
                    user.subscribe_to_tags = form.subscribe_to_tags.data
                    user.part_of_fandom = form.part_of_fandom.data
                    user.enable_tag_bundles = form.enable_tag_bundles.data
                    user.always_show_tags_alphabetical = form.always_show_tags_alphabetical.data
                    user.display_url_under_title = form.display_url_under_title.data
                    user.show_global_bookmark_counts = form.show_global_bookmark_counts.data
                    user.show_exact_datetime_on_bookmarks = form.show_exact_datetime_on_bookmarks.data
                    user.add_bookmarks_private_by_default = form.add_bookmarks_private_by_default.data
                    user.enable_public_profile = form.enable_public_profile.data
                    user.enable_privacy_mode = form.enable_privacy_mode.data

                    db.session.commit()
                    flash(f'Preferences updated for user "{user.username}".', 'success')
                    return redirect(url_for('admin_page'))
            # If no form was matched
            flash('Invalid form submission.', 'error')

    # Initialize edit forms for each user
    for user in users:
        form = AdminEditUserForm(user=user, prefix=f'user_{user.id}', obj=user)  # Pass 'user' here
        edit_forms[user.id] = form

    return render_template('admin.html', users=users, recent_links=recent_links, edit_forms=edit_forms, registration_form=registration_form)

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

@app.route('/fqa')
@login_required
def faq():
    return render_template('faq.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user

    # Statistics for the profile
    total_bookmarks = user.links.count()
    public_bookmarks = user.links.filter_by(private=False).count()
    private_bookmarks = user.links.filter_by(private=True).count()
    unread_bookmarks = user.links.filter_by(read_later=True).count()
    number_of_tags = (
        db.session.query(func.count(func.distinct(Tag.id)))
        .join(link_tags, Tag.id == link_tags.c.tag_id)
        .join(Link, Link.id == link_tags.c.link_id)
        .filter(Link.user_id == user.id)
        .scalar()
    )
    oldest_bookmark = user.links.order_by(Link.created_at.asc()).first()
    newest_bookmark = user.links.order_by(Link.created_at.desc()).first()
    oldest_bookmark_date = oldest_bookmark.created_at if oldest_bookmark else None
    newest_bookmark_date = newest_bookmark.created_at if newest_bookmark else None

    form = ImportForm()
    if form.validate_on_submit():
        file = form.json_file.data
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            flash('Invalid JSON file. Please upload a valid Firefox bookmarks JSON file.', 'error')
        else:
            import_count = 0
            base_timestamp = datetime.utcnow()

            def process_bookmarks(bookmarks):
                nonlocal import_count, base_timestamp
                for item in bookmarks:
                    if item.get('type') == 'text/x-moz-place':
                        uri = item.get('uri')
                        title = item.get('title')
                        tags = item.get('tags', [])

                        if not uri or not title:
                            continue

                        link = Link(
                            url=uri,
                            title=title,
                            user_id=user.id,
                            private=False,
                            created_at=base_timestamp + timedelta(seconds=import_count),
                            updated_at=base_timestamp + timedelta(seconds=import_count),
                        )
                        db.session.add(link)
                        db.session.flush()

                        if isinstance(tags, str):
                            tags = [tag.strip() for tag in tags.replace(',', ' ').split()]
                        for tag_name in tags:
                            tag = Tag.query.filter_by(name=tag_name).first()
                            if not tag:
                                tag = Tag(name=tag_name)
                                db.session.add(tag)
                            link.tags.append(tag)

                        import_count += 1
                    elif 'children' in item:
                        process_bookmarks(item['children'])

            process_bookmarks(data.get('children', []))
            db.session.commit()
            flash(f'Successfully imported {import_count} bookmarks.', 'success')
            return redirect(url_for('profile'))

    return render_template(
        'profile.html',
        user=user,
        total_bookmarks=total_bookmarks,
        public_bookmarks=public_bookmarks,
        private_bookmarks=private_bookmarks,
        unread_bookmarks=unread_bookmarks,
        number_of_tags=number_of_tags if number_of_tags else 0,
        oldest_bookmark_date=oldest_bookmark_date,
        newest_bookmark_date=newest_bookmark_date,
        form=form,
    )

@app.route('/read_redirect/<int:link_id>')
@login_required
def read_redirect(link_id):
    link = Link.query.get_or_404(link_id)
    
    if link.user_id != current_user.id:
        abort(403)
    
    if current_user.mark_toread_as_read_on_click and link.read_later:
        link.read_later = False
        db.session.commit()
        flash(f"Marked '{link.title}' as read.", "success")
    
    return redirect(link.url)

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_bookmarks():
    form = ImportForm()
    if form.validate_on_submit():
        file = form.json_file.data
        try:
            # Attempt to load the JSON data
            data = json.load(file)
        except json.JSONDecodeError:
            flash('Invalid JSON file. Please upload a valid Firefox bookmarks JSON file.', 'error')
            return redirect(url_for('import_bookmarks'))
        except Exception as e:
            flash(f'An error occurred while reading the file: {e}', 'error')
            return redirect(url_for('import_bookmarks'))
        
        # Initialize a counter for imported bookmarks
        import_count = 0

        # Base timestamp: the current UTC time at the start of import
        base_timestamp = datetime.utcnow()

        def process_bookmarks(bookmarks):
            nonlocal import_count, base_timestamp
            for item in bookmarks:
                if item.get('type') == 'text/x-moz-place':
                    uri = item.get('uri')
                    title = item.get('title')
                    tags = item.get('tags', [])  # Fetch tags if present

                    if not uri or not title:
                        continue  # Skip entries without URI or title

                    # Create a new Link instance with a unique created_at timestamp
                    link = Link(
                        url=uri,
                        title=title,
                        user_id=current_user.id,
                        private=False,  # Default to public; modify if needed
                        read_later=False,
                        created_at=base_timestamp + timedelta(seconds=import_count),  # Unique timestamp
                        updated_at=base_timestamp + timedelta(seconds=import_count)   # Keep updated_at consistent
                    )
                    db.session.add(link)
                    db.session.flush()  # Assign an ID to the link

                    # Handle tags appropriately
                    if isinstance(tags, str):
                        # Split tags by comma or space if multiple tags are in a single string
                        tags = [tag.strip() for tag in tags.replace(',', ' ').split()]
                    elif isinstance(tags, list):
                        tags = [tag.strip() for tag in tags]
                    else:
                        tags = []  # If tags are neither string nor list, ignore

                    for tag_name in tags:
                        if not tag_name:
                            continue  # Skip empty tag names
                        tag = Tag.query.filter_by(name=tag_name).first()
                        if not tag:
                            tag = Tag(name=tag_name)
                            db.session.add(tag)
                        link.tags.append(tag)
                    
                    import_count += 1
                elif 'children' in item:
                    # Recursively process nested bookmarks/folders
                    process_bookmarks(item['children'])

        try:
            # Start processing from the root's children
            root_children = data.get('children', [])
            process_bookmarks(root_children)
            db.session.commit()
            flash(f'Successfully imported {import_count} bookmarks.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during import: {e}', 'error')
            return redirect(url_for('import_bookmarks'))
        
        return redirect(url_for('profile'))
    
    return render_template('import.html', form=form)

@app.route('/export')
@login_required
def export_bookmarks():
    """
    Export the current user's bookmarks to a JSON file.
    The JSON structure matches the expected format for import.
    """
    # Query all bookmarks belonging to the current user
    links = Link.query.filter_by(user_id=current_user.id).all()
    
    # Create a list to hold bookmark dictionaries
    bookmarks = []
    for link in links:
        bookmark = {
            "type": "text/x-moz-place",  # Assuming Firefox-like structure
            "uri": link.url,
            "title": link.title,
            "tags": [tag.name for tag in link.tags]
        }
        bookmarks.append(bookmark)
    
    # Define the root JSON structure
    export_data = {
        "children": bookmarks
    }
    
    # Serialize the data to JSON
    json_data = json.dumps(export_data, indent=4)
    
    # Create an in-memory buffer to hold the JSON data
    buffer = io.BytesIO()
    buffer.write(json_data.encode('utf-8'))
    buffer.seek(0)  # Reset buffer position to the beginning
    
    # Send the buffer as a downloadable file
    return send_file(
        buffer,
        as_attachment=True,
        download_name='bookmarks_export.json',
        mimetype='application/json'
    )

@app.route('/tags/autocomplete')
@login_required
def autocomplete_tags():
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify([])
    
    # Determine sorting based on user preference
    if current_user.sort_tags_by_frequency:
        # Order by number of associated links (frequency)
        tags = Tag.query.filter(Tag.name.ilike(f'{query}%')) \
                        .outerjoin(link_tags) \
                        .group_by(Tag.id) \
                        .order_by(func.count(link_tags.c.link_id).desc()) \
                        .limit(10).all()
    else:
        # Order alphabetically
        tags = Tag.query.filter(Tag.name.ilike(f'{query}%')) \
                        .order_by(Tag.name.asc()) \
                        .limit(10).all()
    
    tag_names = [tag.name for tag in tags]
    return jsonify(tag_names)

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
