import re
from flask import Flask, render_template, request, redirect, session, url_for, g, flash
import os
import mysql.connector
import bleach

app = Flask(__name__, template_folder='template')

app.secret_key = os.urandom(24).hex()

sql_injection_pattern = re.compile(r"(\b(union|select|insert|delete|drop|alter|create|concat|substring|from|where|or)\b)|(^')|(--\s*comment)|(/\.\/)|\b(SELECT\s\\s*FROM\s*information_schema\.tables\b)|\b(SELECT\s\\s*FROM\s*information_schema\.columns\s*WHERE\s*table_name\s=\s*'TABLE-NAME-HERE'\b)|\b(SELECT\s*IF\s*\(\s*YOUR-CONDITION-HERE\s*,\s*\(SELECT\s*table_name\s*FROM\s*information_schema\.tables\),\s*'a'\))|\b(>\s*XPATH\s*syntax\s*error:\s*'\\secret'\b)|(\bQUERY-1-HERE;\s*QUERY-2-HERE\b)|(\b(HAVING\s*1=1|AND\s*1=1|AS\s*INJECTX\s*WHERE\s*1=1\s*AND\s*1=1|ORDER\s*BY\s*1--|ORDER\s*BY\s*1#|%' AND\s*8310=8311\s*AND\s*'%'\s*=\s*|sleep|;waitfor\s*delay\s*'0:0:5'--|pg_sleep|SLEEP\(5\)#)\b)", re.IGNORECASE)

xss_pattern = re.compile(r"<\s*script[^>]*>[^<]*<\s*/\s*script\s*>", re.IGNORECASE)

def is_input_safe(input_str):
    if xss_pattern.search(input_str):
        raise ValueError('XSS attack detected.')
    if sql_injection_pattern.search(input_str):
        raise ValueError('Invalid input. Possible SQL injection detected.')
    return True

def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(
            host="localhost",
            user="root",
            password="admin",
            database="sys"
        )
    return g.db

def close_db():
    if 'db' in g:
        g.db.close()

@app.before_request
def before_request():
    g.db = get_db()
    g.cursor = g.db.cursor()

@app.teardown_appcontext
def teardown_appcontext(error=None):
    close_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        

        # Check for specific credentials to block
        if username == 'ADMIN' and password == 'ADMIN':
            return render_template('index.html', error_message='Invalid username or password. Please try again.')

        if session.get('login_attempts', 0) >= 4:
            flash('Too many unsuccessful login attempts. Please try again later.', 'error')
            return render_template('index.html', error_message='Login attempts error', show_attempts_error=True)

        # Use parameterized queries to prevent SQL injection
        sql = "SELECT * FROM usrs WHERE name = %s AND password = %s"
        values = (username, password)

        if not is_input_safe(username) or not is_input_safe(password):
            raise ValueError('Invalid input. Possible SQL injection or XSS attack detected.')

        db = get_db()
        cursor = db.cursor()

        cursor.execute(sql, values)
        user = cursor.fetchone()

        cursor.fetchall()
        cursor.close()

        if user:
            session['login_attempts'] = 0
            if username == 'admin' and password == 'admin':
                log_login(username, 200, request.remote_addr)  # Log successful admin login
                session['authenticated'] = {'username': username, 'password': password}
                return redirect(url_for('admin'))
            else:
                log_login(username, 200,request.remote_addr)  # Log successful user login
                return redirect(url_for('success', username=bleach.clean(username)))
        else:
            session['login_attempts'] = session.get('login_attempts', 0) + 1

            if session['login_attempts'] >= 4:
                flash('Too many unsuccessful login attempts. Please try again later.', 'error')
                return render_template('index.html', error_message='Login attempts error', show_attempts_error=True)

            log_login(username, 401,request.remote_addr)  # Log unsuccessful login attempt
            return render_template('index.html', error_message='Invalid username or password. Please try again.')

    except ValueError as e:
        log_login(username, 500,request.remote_addr)  # Log status code 500 for invalid input
        return str(e), 500
    except Exception as e:
        log_login(username, 500,request.remote_addr)  # Log status code 500 for other exceptions
        app.logger.error(f"Exception: {str(e)}")
        return str(e), 500
@app.route('/admin')
def admin():
    if session.get('authenticated') and session['authenticated']['username'] == 'admin' and session['authenticated']['password'] == 'admin':
        login_logs = get_login_logs()
        return render_template('admin.html', login_logs=login_logs)
    else:
        flash('Unauthorized access to admin page.', 'error')
        return redirect(url_for('index')) 
def get_login_logs():
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        sql = "SELECT * FROM login_logs ORDER BY timestamp DESC LIMIT 100"
        cursor.execute(sql)

        login_logs = cursor.fetchall()
        cursor.close()

        return login_logs
    except mysql.connector.Error as err:
        app.logger.error(f"Database error: {err}")
        return []
    except Exception as e:
        app.logger.error(f"Exception: {str(e)}")
        return []

@app.route('/success')
def success():
    username = request.args.get('username')
    return render_template('success.html', username=username)

def log_login(username, status_code,ip):
    try:
        db = get_db()
        cursor = db.cursor()

        sql = "INSERT INTO login_logs (username, status_code,ip) VALUES (%s, %s,%s)"
        values = (username, status_code,ip)
        cursor.execute(sql, values)

        db.commit()
        cursor.close()
    except mysql.connector.Error as err:
        app.logger.error(f"Database error: {err}")
    except Exception as e:
        app.logger.error(f"Exception: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True)