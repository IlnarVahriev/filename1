from flask import Flask, request, render_template, redirect, session
import sqlite3, os, hashlib

app = Flask(__name__)
app.secret_key = 'super_secret_key_123'

DB = 'app.db'

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

@app.route('/')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        query = "SELECT * FROM users WHERE login='%s' AND password='%s'" % (
            login, hashlib.md5(password.encode()).hexdigest()
        )
        conn = db()
        try:
            user = conn.execute(query).fetchone()
        except Exception as e:
            user = None
            error = f"SQL error: {e}"
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['login'] = user['login']
            return redirect('/profile')
        if not error:
            error = 'Неверный логин или пароль'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET','POST'])
def register():
    error = None
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        email = request.form['email']
        conn = db()
        try:
            pwd = hashlib.md5(password.encode()).hexdigest()
            conn.execute("INSERT INTO users (login,password,email) VALUES (?,?,?)",
                         (login, pwd, email))
            conn.commit()
            return redirect('/login')
        except Exception as e:
            error = str(e)
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
    if 'user_id' not in session:
        return redirect('/login')
    conn = db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not u:
        return "Not found", 404
    return render_template('profile.html', user=u, public=True)

@app.route('/notes', methods=['GET','POST'])
def notes():
    u = current_user()
    if not u:
        return redirect('/login')
    conn = db()
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        conn.execute("INSERT INTO notes (user_id,title,content) VALUES (?,?,?)",
                     (u['id'], title, content))
        conn.commit()
    rows = conn.execute("SELECT * FROM notes WHERE user_id=?", (u['id'],)).fetchall()
    conn.close()
    return render_template('notes.html', notes=rows)

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect('/login')
    conn = db()
    users = conn.execute("SELECT id,login,role,email,secret_note FROM users").fetchall()
    conn.close()
    return render_template('admin.html', users=users)

@app.route('/debug')
def debug():
    u = current_user()
    return {
        'secret_key': app.secret_key,
        'session': dict(session),
        'user': dict(u) if u else None,
        'env': dict(os.environ)
    }

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)