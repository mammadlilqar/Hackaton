import re
from flask import Flask, render_template, request, redirect, session, url_for, g, flash
import os
import mysql.connector
import bleach

app = Flask(__name__, template_folder='template')

app.secret_key = os.urandom(24).hex()

sql_injection_pattern = re.compile(r"(\b(union|select|insert|delete|drop|alter|create|concat|substring|from|where|or)\b)|(^')|(--\s*comment)|(/\.\/)|\b(SELECT\s\\s*FROM\s*information_schema\.tables\b)|\b(SELECT\s\\s*FROM\s*information_schema\.columns\s*WHERE\s*table_name\s=\s*'TABLE-NAME-HERE'\b)|\b(SELECT\s*IF\s*\(\s*YOUR-CONDITION-HERE\s*,\s*\(SELECT\s*table_name\s*FROM\s*information_schema\.tables\),\s*'a'\))|\b(>\s*XPATH\s*syntax\s*error:\s*'\\secret'\b)|(\bQUERY-1-HERE;\s*QUERY-2-HERE\b)|(\b(HAVING\s*1=1|AND\s*1=1|AS\s*INJECTX\s*WHERE\s*1=1\s*AND\s*1=1|ORDER\s*BY\s*1--|ORDER\s*BY\s*1#|%' AND\s*8310=8311\s*AND\s*'%'\s*=\s*|sleep|;waitfor\s*delay\s*'0:0:5'--|pg_sleep|SLEEP\(5\)#)\b)", re.IGNORECASE)

# XSS pattern
xss_pattern = re.compile(r"<\s*script[^>]*>[^<]*<\s*/\s*script\s*>", re.IGNORECASE)


def is_input_safe(input_str):
    # Check for potential XSS
    if xss_pattern.search(input_str):
        raise ValueError('XSS attack detected.')
    # Check for potential SQL injection
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
    return render_template('index.html')

# ... other routes ...

# ... (your existing code)

@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user is already blocked
        if session.get('login_attempts', 0) >= 4:
            # Display error message on the login form
            flash('Too many unsuccessful login attempts. Please try again later.', 'error')
            return render_template('index.html', error_message='Login attempts error', show_attempts_error=True)

        # Validate the user against potential SQL injection and XSS
        if not is_input_safe(username) or not is_input_safe(password):
            raise ValueError('Invalid input. Possible SQL injection or XSS attack detected.')

        sql = "SELECT * FROM usrs WHERE name = %s AND password = %s"
        values = (username, password)

        # Create a new database connection and cursor
        db = get_db()
        cursor = db.cursor()

        cursor.execute(sql, values)
        user = cursor.fetchone()

        # Fetch all results before closing the cursor
        cursor.fetchall()

        # Close the cursor
        cursor.close()

        if user:
            session['login_attempts'] = 0

            if username == 'admin' and password == 'admin':
                # Authenticate as 'admin' with password 'admin'
                session['authenticated'] = {'username': username, 'password': password}
                return redirect(url_for('admin'))
            else:
                # User is valid, redirect to success page
                return redirect(url_for('success', username=bleach.clean(username)))
        else:
            # Increment the login attempts
            session['login_attempts'] = session.get('login_attempts', 0) + 1

            # Check if the login attempts exceeded the limit
            if session['login_attempts'] >= 4:
                flash('Too many unsuccessful login attempts. Please try again later.', 'error')
                return render_template('index.html', error_message='Login attempts error', show_attempts_error=True)

            # User is not valid, render the login page with an error message
            return render_template('index.html', error_message='Invalid username or password. Please try again.')

    except ValueError as e:
        # Catch the ValueError and return a 500 Internal Server Error
        return str(e), 500
    except Exception as e:
        # Log other exceptions and re-raise them to let Flask handle them
        app.logger.error(f"Exception: {str(e)}")
        raise
# ... (your existing code)


@app.route('/admin')
def admin():
    # Check if the user is authenticated as 'ilqar' with password 'Mammadli_2004'
    if session.get('authenticated') and session['authenticated']['username'] == 'admin' and session['authenticated']['password'] == 'admin':
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