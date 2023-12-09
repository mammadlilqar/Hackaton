from flask import Flask, render_template, request, redirect, url_for, g, session, flash
import mysql.connector
import os
import bleach
import re

app = Flask(__name__, template_folder='template')
app.secret_key = os.urandom(24).hex()

sql_injection_pattern = re.compile(r"(\b(union|select|insert|delete|drop|alter|create)\b)|(^')", re.IGNORECASE)

def is_input_safe(input_str):
    return not bool(sql_injection_pattern.search(input_str))

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

# Register the functions to get and close the database connection with the app context
@app.before_request
def before_request():
    g.db = get_db()
    g.cursor = g.db.cursor()

@app.teardown_appcontext
def teardown_appcontext(error=None):
    close_db()

@app.route('/')
def index():
    error_message = request.args.get('error_message', '')
    return render_template('index.html', error_message=error_message)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Check if the user is already blocked
    if session.get('login_attempts', 0) >= 4:
        flash('Too many unsuccessful login attempts. Please try again later.', 'error')
        return redirect(url_for('index', error_message='Login attempts error'))
    
    if not is_input_safe(username) or not is_input_safe(password):
     raise ValueError('Invalid input. Possible SQL injection detected.')

    sql = "SELECT * FROM usrs WHERE name = %s AND password = %s"
    values = (username, password)

    db = get_db()
    cursor = db.cursor()

    cursor.execute(sql, values)
    user = cursor.fetchone()

    cursor.close()

    if user:
        # Reset login attempts upon successful login
        session['login_attempts'] = 0

        if username == 'ilqar' and password == '1':
            # Authenticate as 'ilqar' with password '1'
            session['authenticated'] = {'username': username, 'password': password}
            return redirect(url_for('admin'))
        else:
            # For other users, redirect to success.html (this can be adjusted based on your requirements)
            return redirect(url_for('success', username=username))
    else:
        # Increment the login attempts
        session['login_attempts'] = session.get('login_attempts', 0) + 1
        flash('Invalid username or password. Please try again.', 'error')
        return redirect(url_for('index', error_message='Invalid username or password. Please try again.'))

@app.route('/admin')
def admin():
    # Check if the user is authenticated as 'ilqar' with password 'Mammadli_2004'
    if session.get('authenticated') and session['authenticated']['username'] == 'ilqar' and session['authenticated']['password'] == '1':
        return render_template('admin.html')
    else:
        flash('Unauthorized access to admin page.', 'error')
        return redirect(url_for('index'))

@app.route('/success')
def success():
    # Retrieve the username from the query parameters
    username = request.args.get('username')
    return render_template('success.html', username=username)

if __name__ == '__main__':
    # Run the Flask app in debug mode
    app.run(debug=True)