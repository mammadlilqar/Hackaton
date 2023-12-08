from flask import Flask, render_template, request, redirect, url_for, g
import mysql.connector

app = Flask(__name__, template_folder='template')

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

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Validate the user against the database
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
        # User is valid, redirect to success page
        return redirect(url_for('success', username=username))
    else:
        # User is not valid, render the login page with an error message
        return render_template('index.html', error_message='Invalid username or password. Please try again.')

@app.route('/success')
def success():
    # Retrieve the username from the query parameters
    username = request.args.get('username')
    return render_template('success.html', username=username)

if __name__ == '__main__':
    # Run the Flask app in debug mode
    app.run(debug=True)
