from flask import Flask, render_template, request, redirect, url_for, session, flash
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
                role TEXT NOT NULL DEFAULT 'user'
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

        role = request.form.get('role', 'user')  # Default to 'user' if role is not provided

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
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
            cursor.execute('SELECT id, password, role FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

        if user and check_password_hash(user[1], password):  # Check hashed password
            session['username'] = username
            session['user_id'] = user[0]  # Store user ID
            session['role'] = user[2]     # Store user role
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('login'))

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
        cursor.execute('SELECT id, title, artist, filename, thumbnail, user_id FROM songs')
        songs = cursor.fetchall()

    return render_template('player.html', songs=songs)

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


@app.route('/manage_users')
def manage_users():
    if 'username' not in session or session.get('role') != 'moderator':
        return redirect(url_for('login'))

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role FROM users')
        users = cursor.fetchall()

    return render_template('manage_users.html', users=users)

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    app.run(debug=True)
