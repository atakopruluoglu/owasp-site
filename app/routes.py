from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
from .user_auth import authenticate, write_user

from app import app

@app.route('/create_user', methods=['POST'])
def create_user():
    username = request.form['username']
    password = request.form['password']
    if not authenticate(username, password):
        write_user(username, password)
        return "User created successfully" #Parola düz metin olarak saklanıyor. Broken Authentication kategorisinde değerlendirilebilir -Nilay
    else:
        return "User already exists"



def read_users():
    users_file = os.path.join(os.path.dirname(__file__), 'user_data', 'users.txt')
    users = {}
    with open(users_file, 'r') as file:
        for line in file:
            username, password = line.strip().split(',')
            users[username] = password # Parola düz metin olarak okunuyor -Nilay
    return users

def authenticate(username, password):
    users = read_users()
    if username in users:
        stored_password = users[username]
        provided_password = password
        if provided_password == stored_password:
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
        # Authenticate user before checking credentials
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






# AS06: Security Misconfiguration
@app.route('/AS06', methods=['GET', 'POST'])
def AS06():
    if request.method == 'POST':
        # Simulate a configuration change that should not be accessible
        if 'config_change' in request.form:
            return "Configuration changed (insecurely)."
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
        if request.args.get('action')=="save_user":
            print("save user: ", request.form)
            InsecureDeserialization.SaveUser(request.form["username"], request.form["password"])
            return render_template('AS08.html', processed_text_succ="User Created.")
        
        if request.args.get('action')=="login":
            ## user check
            if InsecureDeserialization.ValidateUser(request.form["username"],request.form["password"]):
                print("Validation succ for user login")
            else:
                print("Validation fail for user login")
                return render_template('AS08.html',processed_text="The Username or Password is Incorrect, Try again")
            ## CAPTCHA
            # wrong validation check
            is_ok, msg= InsecureDeserialization.ValidateCaptcha(app.config, captcha, request.form["captcha"])
            if is_ok:
                return render_template('AS08_redirect.html', processed_text_succ=msg)
            else:
                return render_template('AS08.html',processed_text=msg)
    
    elif request.method == 'GET':
        if request.args.get('action') == "create":
            print("Create action requested redirect to create user page..")
            return render_template('AS08_redirect_create_page.html')
        return render_template('AS08.html')

    return render_template('AS08.html')

# AS09: Using Components with Known Vulnerabilities
@app.route('/AS09')
def AS09():
    return render_template('AS09.html')

# AS10: Insufficient Logging & Monitoring
@app.route('/AS10')
def AS10():
    return render_template('AS10.html')

@app.route('/login', methods=['POST'])
def login():
    if authenticate(request.form['username'], request.form['password']): #Oturum sabitleme (session fixation) yapılmıyor. Oturum yönetimi yok. -Nilay
        return redirect(url_for('index'))  # Redirect to the homepage after successful login
    return "Login failed"

@app.route('/logout')
def logout():
    # Perform logout operations if needed
    return redirect(url_for('index'))  # Redirect to the homepage after logout


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the file part is in the request
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            # Securely save the file
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
        output = os.popen(command).read()  # This is vulnerable to command injection
        return f"Command output: <pre>{output}</pre>"
    return render_template('AS13.html')


#idor
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