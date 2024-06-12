import os
from hashlib import sha256

def read_users():
    users_file = os.path.join(os.path.dirname(__file__), 'user_data', 'users.txt')
    users = {}
    with open(users_file, 'r') as file:
        for line in file:
            username, password_hash = line.strip().split(',')
            users[username] = password_hash
    return users

def write_user(username, password):
    users_file = os.path.join(os.path.dirname(__file__), 'user_data', 'users.txt')
    with open(users_file, 'a') as file:
        password_hash = sha256(password.encode()).hexdigest()
        file.write(f"{username},{password_hash}\n")

def authenticate(username, password):
    users = read_users()
    if username in users:
        stored_password_hash = users[username]
        provided_password_hash = sha256(password.encode()).hexdigest()
        if provided_password_hash == stored_password_hash:
            return True
    return False
