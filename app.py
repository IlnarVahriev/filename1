from flask import Flask, request, render_template, redirect, session, abort
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, re

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    
    SESSION_COOKIE_SAMESITE='Lax',   
    SESSION_COOKIE_SECURE=bool(os.environ.get("HTTPS")),  
)

DB = 'app.db'
LOGIN_RE = re.compile(r'^[A-Za-z0-9_]{3,32}$')    
PWD_MIN = 8

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def current_user():
    if 'user_id' not in session:
        return None
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    conn.close()
    return u

def admin_required(f):
    """Уязв. №6: серверная проверка роли, а не скрытие кнопки."""
    @wraps(f)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            return redirect('/login')
        if u['role'] != 'admin':
            abort(403)
        return f(*a, **kw)
    return wrapper

@app.after_request
def security_headers(resp):
    resp.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    return resp

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        login = request.form.get('login', '')
        password = request.form.get('password', '')
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['login'] = user['login']
            return redirect('/profile')
        error = 'Неверный логин или пароль'  
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        login = request.form.get('login', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')

       
        if not LOGIN_RE.match(login):
            error = 'Логин: 3–32 символа, латиница, цифры, _'
        elif len(password) < PWD_MIN:
            error = f'Пароль не короче {PWD_MIN} символов'
        elif '@' not in email or len(email) > 254:
            error = 'Некорректный email'
        else:
            conn = db()
            try:
                conn.execute(
                    "INSERT INTO users (login,password,email) VALUES (?,?,?)",
                    (login, generate_password_hash(password), email)
                )
                conn.commit()
                return redirect('/login')
            except sqlite3.IntegrityError:
                error = 'Логин уже занят'   
            except Exception:
                app.logger.exception("register failed")
                error = 'Ошибка регистрации'
            finally:
                conn.close()
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/profile')
def profile():
    u = current_user()
    if not u:
        return redirect('/login')
    return render_template('profile.html', user=u)

@app.route('/user/<int:uid>')
def user_view(uid):
    me = current_user()
    if not me:
        return redirect('/login')
    if uid != me['id'] and me['role'] != 'admin':
        abort(403)
    conn = db()
    u = conn.execute("SELECT id,login,role FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not u:
        abort(404)
    return render_template('profile.html', user=u, public=True)

@app.route('/notes', methods=['GET', 'POST'])
def notes():
    u = current_user()
    if not u:
        return redirect('/login')
    conn = db()
    if request.method == 'POST':
        title = request.form.get('title', '')[:200]
        content = request.form.get('content', '')[:5000]
        conn.execute("INSERT INTO notes (user_id,title,content) VALUES (?,?,?)",
                     (u['id'], title, content))
        conn.commit()
    rows = conn.execute("SELECT * FROM notes WHERE user_id=?", (u['id'],)).fetchall()
    conn.close()
    return render_template('notes.html', notes=rows)

@app.route('/admin')
@admin_required          
def admin():
    conn = db()
    users = conn.execute("SELECT id,login,role,email,secret_note FROM users").fetchall()
    conn.close()
    return render_template('admin.html', users=users)


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)