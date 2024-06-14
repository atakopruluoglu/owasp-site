from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import logging
from logging.handlers import RotatingFileHandler
import os
from .user_auth import authenticate, write_user
from .insecure_deserialization import InsecureDeserialization

from app import app
users_data = {
    'admin': {
        'id': '1',
        'name': 'Admin',
        'email': 'admin@example.com'
    },
    'bob': {
        'id': '2',
        'name': 'Bob',
        'email': 'bob@example.com'
    }
}

# Configure logging ELİF
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s')
log_file = os.path.join('app', 'app.log')

file_handler = RotatingFileHandler(log_file, maxBytes=10240, backupCount=10)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)

app.logger.addHandler(file_handler)

@app.route('/log_message/<message>')
def log_message(message):
    logging.info(f"Received message: {message}")
    return f"Logged message: {message}"

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# For captcha session
captcha = InsecureDeserialization.CreateCaptcha(app)

@app.route('/create_user', methods=['POST'])
def create_user():
    username = request.form['username']
    password = request.form['password']
    if not authenticate(username, password):
        write_user(username, password)
        return "User created successfully"
    else:
        return "User already exists"

def read_users():
    users_file = os.path.join(os.path.dirname(__file__), 'user_data', 'users.txt')
    users = {}
    with open(users_file, 'r') as file:
        for line in file:
            username, password = line.strip().split(',')
            users[username] = password
    return users

def authenticate(username, password):
    users = read_users()
    if username in users:
        stored_password = users[username]
        if password == stored_password:
            return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/AS01', methods=['GET', 'POST'])
def AS01():
    if request.method == 'POST':
        if not authenticate(request.form['username'], request.form['password']):
            return "Unauthorized"
        user_id = request.form['user_id']
        query = f"SELECT * FROM users WHERE id = {user_id}"  # This is vulnerable to SQL Injection
        return f"Query: {query}"
    return render_template('AS01.html')

# AS02: Broken Authentication
@app.route('/AS02', methods=['GET', 'POST'])
def AS02():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not authenticate(username, password):
            return "Unauthorized"
        if username == 'admin' and password == 'admin':  # This is vulnerable to hardcoded credentials
            return "Logged in as admin"
        return "Login failed"
    return render_template('AS02.html')

# AS03: Sensitive Data Exposure
@app.route('/AS03')
def AS03():
    sensitive_data = "User's sensitive data exposed here."  # This demonstrates sensitive data exposure
    return render_template('AS03.html', sensitive_data=sensitive_data)

# AS04: XML External Entities (XXE)
@app.route('/AS04', methods=['GET', 'POST'])
def AS04():
    if request.method == 'POST':
        xml_input = request.form['xml_input']
        return f"Received XML: {xml_input}"  # This demonstrates XML External Entities (XXE) vulnerability
    return render_template('AS04.html')

# AS05: Broken Access Control
@app.route('/AS05', methods=['GET', 'POST'])
def AS05():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('AS05'))
    return render_template('as05.html')

# # Secret key for session management (required for flash messages)
# app.secret_key = 'your_secret_key_here'

# @app.route('/AS06', methods=['GET', 'POST'])
# def AS06():
#     if request.method == 'POST':
#         if 'config_change' in request.form:
#             # Implement proper authorization check (e.g., check if user is admin)
#             if is_admin(request):
#                 # Perform secure configuration change
#                 perform_secure_config_change(request.form['config_change'])
#                 flash('Configuration changed securely!')
#             else:
#                 flash('Unauthorized access!')
#             return redirect(url_for('AS06'))
#     return render_template('AS06.html')

# def is_admin(request):
#     # Replace with actual authentication logic (e.g., check user role)
#     return request.form.get('username') == 'admin'  # Example: Check if user is admin

# def perform_secure_config_change(config_change):
#     # Implement secure configuration change logic here
#     # Example: Write changes to a secure configuration file/database
#     # Example: Log the configuration change event
#     print(f"Secure configuration change: {config_change}")


@app.route('/AS06', methods=['GET', 'POST'])
def A06():
    if request.method == 'POST':
        # Vulnerable action using outdated component
        result = vulnerable_library.vulnerable_function(request.form['user_input'])
        return f"Result: {result}"
    return render_template('AS06.html')




# AS07: Cross-Site Scripting (XSS)
@app.route('/AS07', methods=['GET', 'POST'])
def AS07():
    if request.method == 'POST':
        user_input = request.form['user_input']
        return f"Received input: {user_input}"  # This demonstrates Cross-Site Scripting (XSS) vulnerability
    return render_template('AS07.html')

# AS08: Insecure Deserialization
@app.route('/AS08', methods=['GET', 'POST'])
def AS08():
    if request.method == 'POST':
        if request.args.get('action') == "save_user":
            InsecureDeserialization.SaveUser(request.form["username"], request.form["password"])
            return render_template('AS08.html', processed_text_succ="User Created.")
        if request.args.get('action') == "login":
            if InsecureDeserialization.ValidateUser(request.form["username"], request.form["password"]):
                return render_template('AS08.html', processed_text_succ="Login Successful.")
            else:
                return render_template('AS08.html', processed_text_fail="Login Failed.")
    return render_template('AS08.html')

# AS09: Using Components with Known Vulnerabilities
@app.route('/AS09', methods=['GET', 'POST'])
def AS09():
    if request.method == 'POST':
        file = request.files['file']
        file.save(os.path.join('/tmp', file.filename))
        return "File uploaded"
    return render_template('AS09.html')

# AS10: Insufficient Logging & Monitoring
@app.route('/AS10')
def AS10():
    if request.args.get('username') == 'admin':
        print(f"Admin accessed with IP: {request.remote_addr}")
        return "Welcome, admin!"
    return render_template('AS10.html')

@app.route('/login', methods=['POST'])
def login():
    if authenticate(request.form['username'], request.form['password']):
        return redirect(url_for('index'))  # Redirect to the homepage after successful login
    return "Login failed"

@app.route('/logout')
def logout():
    return redirect(url_for('index'))  # Redirect to the homepage after logout

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('AS05'))
    return render_template('upload.html')

@app.route('/AS11', methods=['GET', 'POST'])
def AS11():
    if request.method == 'POST':
        if not authenticate(request.form['username'], request.form['password']):
            return "Unauthorized"
        user_id = request.form['user_id']
        query = f"SELECT * FROM users WHERE id = {user_id}"
        return f"Query: {query}"
    return render_template('AS11.html')

# AS13: Command Injection
@app.route('/AS13', methods=['GET', 'POST'])
def AS13():
    if request.method == 'POST':
        command = request.form['command']
        
        # You should validate and sanitize the command input here to prevent misuse
        
        # Example: Check if the command is attempting to download a specific file
        if command.startswith('download '):
            filename = command.split(' ')[1]
            file_path = os.path.join(app.root_path, filename)
            
            # Check if the file exists
            if os.path.exists(file_path):
                # Send the file for download
                return send_file(file_path, as_attachment=True)
            else:
                return f"File '{filename}' not found."
        
        # Handle other commands or actions based on your application's logic
        
        return "Command executed."
    
    return render_template('AS13.html')


# IDOR
@app.route('/AS12', methods=['GET', 'POST'])
def AS12():
    if request.method == 'POST':
        username = request.form['username']
        users = read_users()
        user_id = None
        for uid, user_data in users.items():
            if user_data['username'] == username:
                user_id = uid
                break
        if user_id:
            return f"User data for username {username}: User ID: {username}, Email: {users[user_id]['email']}"
        else:
            return "User not found"
    return render_template('as12.html')

@app.route('/user_profile/<username>')
def user_profile(username):
    if username in users_data:
        user_info = users_data[username]
        return render_template('user_profile.html', user=user_info)
    else:
        return "User not found", 404

@app.route('/update_profile/<username>', methods=['POST'])
def update_profile(username):
    if username in users_data:
        users_data[username]['name'] = request.form.get('name')
        users_data[username]['email'] = request.form.get('email')
        return redirect(url_for('user_profile', username=username))
    else:
        return "User not found", 404

@app.route('/AS28', methods=['GET', 'POST'])
def AS28():
    if request.method == 'POST':
        command = request.form['command']
        stream = os.popen(command)
        output = stream.read()
        return f"Command output: <pre>{output}</pre>"
    return render_template('AS28.html')

if __name__ == '__main__':
    app.run(debug=True)



def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Salt ve Hash ile Parola Saklama
        salt = os.urandom(16).hex()  # Rastgele bir salt oluştur
        salted_password = password + salt
        hashed_password_with_salt = generate_password_hash(salted_password, method='sha256')
        
        # Veritabanına kaydetme
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', 
                     (username, hashed_password_with_salt, salt))
        conn.commit()
        conn.close()

        flash('Registration successful!')
        return redirect(url_for('giris'))
    return render_template('register.html')

@app.route('/giris', methods=['GET', 'POST'])
def giris():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user:
            # Salted hash ile parola doğrulama
            salted_password = password + user['salt']
            if check_password_hash(user['password'], salted_password):
                flash('Login successful!')
                return redirect(url_for('index'))
            else:
                flash('Invalid credentials')
        else:
            flash('Invalid credentials')
    return render_template('giris.html')


@app.route('/logs')
def logs():
    with open('app.log', 'r') as log_file:
        logs = log_file.readlines()
    return render_template('logs.html', logs=logs)
