from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import mimetypes
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Load configurations from environment variables
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['UPLOAD_FOLDER'] = 'static/songs'
app.config['ALLOWED_EXTENSIONS'] = {'mp3'}
app.config['SESSION_COOKIE_SECURE'] = True  # Secure cookies for HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JS access to cookies

# Database initialization
def init_db():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                profile_picture TEXT  -- New column for profile picture
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS songs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                artist TEXT NOT NULL,
                filename TEXT NOT NULL,
                thumbnail TEXT,  -- New column for thumbnail
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            song_id INTEGER NOT NULL,
            reporter_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (song_id) REFERENCES songs(id),
            FOREIGN KEY (reporter_id) REFERENCES users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS playlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS playlist_songs (
                playlist_id INTEGER,
                song_id INTEGER,
                PRIMARY KEY (playlist_id, song_id),
                FOREIGN KEY (playlist_id) REFERENCES playlists(id),
                FOREIGN KEY (song_id) REFERENCES songs(id)
            )
        ''')

        conn.commit()

init_db()

def allowed_file(filename):
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type == 'audio/mpeg' and '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'jpg', 'jpeg', 'png', 'gif'}

@app.route('/')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        profile_picture = request.files['profile_picture']

        role = request.form.get('role', 'user')  # Default to 'user' if role is not provided

        profile_picture_filename = None
        if profile_picture and allowed_image(profile_picture.filename):
            profile_picture_filename = secure_filename(profile_picture.filename)
            profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_picture_filename)
            profile_picture.save(profile_picture_path)

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, role, profile_picture) VALUES (?, ?, ?, ?)',
                          (username, hashed_password, role, profile_picture_filename))
            conn.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password, role, profile_picture FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user[1], password):  # Check hashed password
            session['username'] = username
            session['user_id'] = user[0]  # Store user ID
            session['role'] = user[2]     # Store user role
            session['profile_picture'] = user[3]  # Store profile picture filename
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('profile_picture', None)
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route('/terms-of-service')
def terms_of_service():
    return render_template('tos.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        artist = request.form['artist']
        file = request.files['file']
        thumbnail = request.files['thumbnail']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Save thumbnail if provided
            thumbnail_filename = None
            if thumbnail and allowed_image(thumbnail.filename):
                thumbnail_filename = secure_filename(thumbnail.filename)
                thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename)
                thumbnail.save(thumbnail_path)

            with sqlite3.connect('database.db') as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO songs (title, artist, filename, thumbnail, user_id) VALUES (?, ?, ?, ?, ?)',
                              (title, artist, filename, thumbnail_filename, session['user_id']))
                conn.commit()

            flash('Song uploaded successfully!')
            return redirect(url_for('player'))
        else:
            flash('Invalid file type. Only MP3 files are allowed.')

    return render_template('upload.html')

@app.route('/player')
def player():
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, title, artist, filename, thumbnail, user_id FROM songs ORDER BY id DESC LIMIT 5')
        featured_songs = cursor.fetchall()

        cursor.execute('SELECT id, title, artist, filename, thumbnail, user_id FROM songs')
        all_songs = cursor.fetchall()

    return render_template('player.html', songs=all_songs, featured_songs=featured_songs)

@app.route('/delete_song/<int:song_id>', methods=['POST'])
def delete_song(song_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()

        # Get the song details
        cursor.execute('SELECT user_id, filename FROM songs WHERE id = ?', (song_id,))
        song = cursor.fetchone()

        if not song:
            flash('Song not found.')
            return redirect(url_for('player'))

        # Check if the user is the owner or a moderator
        if session['role'] == 'moderator' or song[0] == session['user_id']:
            # Delete the song file
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], song[1])
            if os.path.exists(filepath):
                os.remove(filepath)

            # Delete the song from the database
            cursor.execute('DELETE FROM songs WHERE id = ?', (song_id,))
            conn.commit()
            flash('Song deleted successfully.')
        else:
            flash('You do not have permission to delete this song.')

    return redirect(url_for('player'))

@app.route('/moderator')
def moderator():
    if 'username' not in session or session.get('role') != 'moderator':
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT songs.id, songs.title, songs.artist, songs.filename, users.username FROM songs JOIN users ON songs.user_id = users.id')
        songs = cursor.fetchall()

    return render_template('moderator.html', songs=songs)

@app.route('/promote/<int:user_id>', methods=['POST'])
def promote_user(user_id):
    if 'username' not in session or session.get('role') != 'moderator':
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET role = ? WHERE id = ?', ('moderator', user_id))
        conn.commit()

    flash('User promoted to moderator.')
    return redirect(url_for('manage_users'))

@app.route('/edit_song/<int:song_id>', methods=['GET', 'POST'])
def edit_song(song_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()

        cursor.execute('SELECT id, title, artist, filename, thumbnail, user_id FROM songs WHERE id = ?', (song_id,))
        song = cursor.fetchone()

        if not song:
            flash('Song not found.')
            return redirect(url_for('player'))

        # Authorization check
        if session['role'] != 'moderator' and song[5] != session['user_id']:
            flash('You do not have permission to edit this song.')
            return redirect(url_for('player'))

        if request.method == 'POST':
            new_title = request.form['title']
            new_artist = request.form['artist']
            new_thumbnail_file = request.files.get('thumbnail')

            new_thumbnail_filename = song[4]  # Keep existing thumbnail by default

            if new_thumbnail_file and allowed_image(new_thumbnail_file.filename):
                new_thumbnail_filename = secure_filename(new_thumbnail_file.filename)
                thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], new_thumbnail_filename)
                new_thumbnail_file.save(thumbnail_path)

            cursor.execute('''
                UPDATE songs SET title = ?, artist = ?, thumbnail = ?
                WHERE id = ?
            ''', (new_title, new_artist, new_thumbnail_filename, song_id))
            conn.commit()

            flash('Song updated successfully.')
            return redirect(url_for('player'))

    return render_template('edit_song.html', song=song)

@app.route('/update_profile_picture', methods=['GET', 'POST'])
def update_profile_picture():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        profile_picture = request.files['profile_picture']

        if profile_picture and allowed_image(profile_picture.filename):
            profile_picture_filename = secure_filename(profile_picture.filename)
            profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_picture_filename)
            profile_picture.save(profile_picture_path)

            with sqlite3.connect('database.db') as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET profile_picture = ? WHERE id = ?',
                              (profile_picture_filename, session['user_id']))
                conn.commit()

            session['profile_picture'] = profile_picture_filename
            flash('Profile picture updated successfully!')
            return redirect(url_for('index'))
        else:
            flash('Invalid file type. Only JPG, JPEG, PNG, and GIF are allowed.')

    return render_template('update_profile_picture.html')

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT title, artist, filename, thumbnail FROM songs WHERE user_id = ?', (session['user_id'],))
        user_songs = cursor.fetchall()
        song_count = len(user_songs)

    return render_template('profile.html',
                           username=session['username'],
                           role=session.get('role', 'user'),
                           profile_picture=session.get('profile_picture'),
                           songs=user_songs,
                           song_count=song_count)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form['username']
        current_password = request.form['current_password']
        new_password = request.form.get('new_password')

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],))
            db_password = cursor.fetchone()[0]

            if check_password_hash(db_password, current_password):
                if new_username:
                    cursor.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, session['user_id']))
                    session['username'] = new_username

                if new_password:
                    hashed_new_password = generate_password_hash(new_password)
                    cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_new_password, session['user_id']))

                conn.commit()
                flash('Profile updated successfully.')
                return redirect(url_for('profile'))
            else:
                flash('Current password is incorrect.')

    return render_template('edit_profile.html', current_username=session['username'])

@app.route('/moderator/reports')
def view_reports():
    if 'username' not in session or session.get('role') != 'moderator':
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT reports.id, reports.reason, reports.timestamp,
                   users.username AS reporter, songs.title, songs.id AS song_id
            FROM reports
            JOIN users ON reports.reporter_id = users.id
            JOIN songs ON reports.song_id = songs.id
        ''')
        reports = cursor.fetchall()

    return render_template('view_reports.html', reports=reports)

@app.route('/delete_report/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    if 'username' not in session or session.get('role') != 'moderator':
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM reports WHERE id = ?', (report_id,))
        conn.commit()

    flash('Report deleted successfully.')
    return redirect(url_for('view_reports'))

@app.route('/report_song/<int:song_id>', methods=['GET', 'POST'])
def report_song(song_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        reason = request.form['reason']
        reporter_id = session['user_id']  # Use the logged-in user's ID

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO reports (song_id, reporter_id, reason)
                    VALUES (?, ?, ?)
                ''', (song_id, reporter_id, reason))
                conn.commit()
                flash('Song reported successfully.')
            except sqlite3.IntegrityError as e:
                flash(f'Error: {e}')

        return redirect(url_for('player'))

    return render_template('report_song.html', song_id=song_id)

@app.route('/update_report_status/<int:report_id>', methods=['POST'])
def update_report_status(report_id):
    if 'username' not in session or session.get('role') != 'moderator':
        return redirect(url_for('login'))

    new_status = request.form['status']
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('UPDATE reports SET status = ? WHERE id = ?', (new_status, report_id))
        conn.commit()

    flash('Report status updated.')
    return redirect(url_for('view_reports'))

@app.route('/manage_users')
def manage_users():
    if 'username' not in session or session.get('role') != 'moderator':
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role FROM users')
        users = cursor.fetchall()

    return render_template('manage_users.html', users=users)

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT username, profile_picture, role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()

        if not user:
            return render_template('404.html'), 404

        cursor.execute('SELECT title, artist, filename, thumbnail FROM songs WHERE user_id = ?', (user_id,))
        user_songs = cursor.fetchall()

    return render_template('user_profile.html',
                           username=user[0],
                           profile_picture=user[1],
                           role=user[2],
                           songs=user_songs)

@app.context_processor
def utility_processor():
    def get_username(user_id):
        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
            user = cursor.fetchone()
            return user[0] if user else "Unknown User"
    return dict(get_username=get_username)

@app.route('/remove_from_playlist/<int:playlist_id>/<int:song_id>', methods=['POST'])
def remove_from_playlist(playlist_id, song_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM playlist_songs WHERE playlist_id = ? AND song_id = ?', (playlist_id, song_id))
        conn.commit()

    flash('Song removed from playlist.')
    return redirect(url_for('view_playlist', playlist_id=playlist_id))

@app.route('/add_to_playlist/<int:song_id>', methods=['GET', 'POST'])
def add_to_playlist(song_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM playlists WHERE user_id = ?', (session['user_id'],))
        playlists = cursor.fetchall()

    if request.method == 'POST':
        playlist_id = int(request.form['playlist_id'])

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO playlist_songs (playlist_id, song_id) VALUES (?, ?)',
                           (playlist_id, song_id))
            conn.commit()
            flash('Song added to playlist.')
        return redirect(url_for('player'))

    return render_template('add_to_playlist.html', playlists=playlists, song_id=song_id)

@app.route('/playlist/<int:playlist_id>')
def view_playlist(playlist_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM playlists WHERE id = ?', (playlist_id,))
        playlist = cursor.fetchone()

        if not playlist:
            flash("Playlist not found.")
            return redirect(url_for('my_playlists'))

        cursor.execute('''
            SELECT songs.id, songs.title, songs.artist, songs.filename, songs.thumbnail
            FROM playlist_songs
            JOIN songs ON playlist_songs.song_id = songs.id
            WHERE playlist_songs.playlist_id = ?
        ''', (playlist_id,))
        songs = cursor.fetchall()

    return render_template('playlist.html', playlist_name=playlist[0], songs=songs)

@app.route('/my_playlists')
def my_playlists():
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM playlists WHERE user_id = ?', (session['user_id'],))
        playlists = cursor.fetchall()

    return render_template('my_playlists.html', playlists=playlists)

@app.route('/create_playlist', methods=['GET', 'POST'])
def create_playlist():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        user_id = session['user_id']

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO playlists (name, user_id) VALUES (?, ?)', (name, user_id))
            conn.commit()

        flash('Playlist created successfully!')
        return redirect(url_for('my_playlists'))

    return render_template('create_playlist.html')

@app.route('/search')
def search():
    query = request.args.get('query', '').strip()
    if not query:
        return redirect(url_for('player'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, title, artist, filename, thumbnail, user_id 
            FROM songs 
            WHERE title LIKE ? OR artist LIKE ?
        ''', (f'%{query}%', f'%{query}%'))
        results = cursor.fetchall()

    return render_template('player.html', songs=results)

@app.route('/recommended')
def recommended():
    if 'username' not in session:
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT songs.id, songs.title, songs.artist, songs.filename, songs.thumbnail, songs.user_id
            FROM songs
            JOIN playlist_songs ON songs.id = playlist_songs.song_id
            GROUP BY songs.id
            ORDER BY COUNT(playlist_songs.playlist_id) DESC
            LIMIT 5
        ''')
        recommended_songs = cursor.fetchall()

    return render_template('recommended.html', recommended_songs=recommended_songs)

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    app.run(debug=True)
