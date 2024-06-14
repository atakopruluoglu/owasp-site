import os

def read_users():
    users_file = os.path.join(os.path.dirname(__file__), 'user_data', 'users.txt')
    users = {}
    with open(users_file, 'r') as file:
        for line in file:
            username, password = line.strip().split(',')
            users[username] = password
    return users

def write_user(username, password):
    users_file = os.path.join(os.path.dirname(__file__), 'user_data', 'users.txt')
    with open(users_file, 'a') as file:
        #password_hash = sha256(password.encode()).hexdigest()
        #Parolayı Hashlemiyoruz. Böylece düz metin olarak saklanıyor. Hashleme fonksiyonu yorum satırı olarak değiştirildi. -Nilay
        file.write(f"{username},{password}\n") #Parola artık düz metin olarak saklanıyor. -Nilay

def authenticate(username, password):
    users = read_users()
    if username in users:
        stored_password = users[username]
        #provided_password = sha256(password.encode()).hexdigest() 
        if password == stored_password: #Hash değerinin bozulması sebebiyle gerekli field'lar düzeltildi.
            return True
    return False
