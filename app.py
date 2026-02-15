from flask import Flask, render_template, request, redirect, session, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'word-game-portal-2026-redblack'

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', 'exe', 'html'}

def init_db():
    conn = sqlite3.connect('games.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, is_admin INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS games 
                 (id INTEGER PRIMARY KEY, title TEXT, description TEXT, 
                  avatar TEXT, file_path TEXT, date TEXT, downloads INTEGER DEFAULT 0)''')
    
    # Создаём админа
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        pwd_hash = generate_password_hash('Mark123458790')
        c.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', ?, 1)", (pwd_hash,))
    conn.commit()
    conn.close()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_games(search=''):
    conn = sqlite3.connect('games.db')
    c = conn.cursor()
    if search:
        c.execute("SELECT * FROM games WHERE title LIKE ? OR description LIKE ? ORDER BY date DESC", 
                 (f'%{search}%', f'%{search}%'))
    else:
        c.execute("SELECT * FROM games ORDER BY date DESC")
    games = c.fetchall()
    conn.close()
    return games

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/games')
def api_games():
    search = request.args.get('search', '')
    games = get_games(search)
    return jsonify([{
        'id': g[0], 'title': g[1], 'description': g[2], 'avatar': g[3], 
        'file': g[4], 'date': g[5], 'downloads': g[6]
    } for g in games])

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data['username']
    password = data['password']
    
    conn = sqlite3.connect('games.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user[2], password):
        session['user_id'] = user[0]
        session['username'] = username
        session['is_admin'] = bool(user[3])
        return jsonify({'success': True, 'is_admin': bool(user[3]), 'username': username})
    return jsonify({'success': False}), 401

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    username = data['username']
    password = data['password']
    
    conn = sqlite3.connect('games.db')
    c = conn.cursor()
    try:
        pwd_hash = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", (username, pwd_hash))
        conn.commit()
        return jsonify({'success': True})
    except:
        return jsonify({'success': False, 'error': 'Пользователь существует'}), 400
    finally:
        conn.close()

@app.route('/api/logout')
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/admin/upload', methods=['POST'])
def admin_upload():
    if not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Доступ запрещён'}), 403
    
    title = request.form['title']
    description = request.form['description']
    avatar = request.files.get('avatar')
    game_file = request.files.get('game_file')
    
    conn = sqlite3.connect('games.db')
    c = conn.cursor()
    
    avatar_path = ''
    if avatar and allowed_file(avatar.filename):
        filename = f"avatar_{datetime.now().timestamp()}_{secure_filename(avatar.filename)}"
        avatar.save(os.path.join(UPLOAD_FOLDER, filename))
        avatar_path = filename
    
    if game_file and allowed_file(game_file.filename):
        filename = f"game_{datetime.now().timestamp()}_{secure_filename(game_file.filename)}"
        game_file.save(os.path.join(UPLOAD_FOLDER, filename))
        file_path = filename
        
        c.execute("INSERT INTO games (title, description, avatar, file_path, date) VALUES (?, ?, ?, ?, ?)",
                 (title, description, avatar_path, file_path, datetime.now().strftime('%Y-%m-%d %H:%M')))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    conn.close()
    return jsonify({'success': False, 'error': 'Файл не загружен'}), 400

@app.route('/download/<int:game_id>')
def download(game_id):
    conn = sqlite3.connect('games.db')
    c = conn.cursor()
    c.execute("SELECT file_path FROM games WHERE id=?", (game_id,))
    result = c.fetchone()
    
    if result:
        c.execute("UPDATE games SET downloads = downloads + 1 WHERE id=?", (game_id,))
        conn.commit()
        conn.close()
        return send_from_directory(UPLOAD_FOLDER, result[0], as_attachment=True)
    
    conn.close()
    return 'Файл не найден', 404

if __name__ == '__main__':
    app.run(debug=True, port=5000)
