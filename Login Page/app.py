from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__, template_folder='template')

# Static database for demonstration purposes
users_database = [
    {'username': 'user', 'password': 'pa'},
    {'username': 'user2', 'password': 'password2'},
]

def validate_user(username, password):
    return any(user['username'] == username and user['password'] == password for user in users_database)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if validate_user(username, password):
        return render_template('success.html')
    else:
        return render_template('index.html', error_message='Invalid username or password. Please try again.')

if __name__ == '__main__':
    app.run(debug=True)
