from flask import render_template, request, redirect, url_for
from hashlib import sha256
import os
from .user_auth import authenticate, write_user
from app import app

# lab Insecure Deserialization
try:
    from .insecure_deserialization import *
except Exception as e:
    print("Error at importing modules for Insecure Deserialization lab. Check for missing libraries..")
    print("Probably, you just need to pip install <exception thrown lib name>")

#for captcha session
captcha= InsecureDeserialization.CreateCaptcha(app)

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
            username, password_hash = line.strip().split(',')
            users[username] = password_hash
    return users

def authenticate(username, password):
    users = read_users()
    if username in users:
        stored_password_hash = users[username]
        provided_password_hash = sha256(password.encode()).hexdigest()
        if provided_password_hash == stored_password_hash:
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
@app.route('/AS05')
def AS05():
    return render_template('AS05.html')

# AS06: Security Misconfiguration
@app.route('/AS06')
def AS06():
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
    if authenticate(request.form['username'], request.form['password']):
        return redirect(url_for('index'))  # Redirect to the homepage after successful login
    return "Login failed"

@app.route('/logout')
def logout():
    # Perform logout operations if needed
    return redirect(url_for('index'))  # Redirect to the homepage after logout