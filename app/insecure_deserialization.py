import uuid 
from flask_sessionstore import Session 
from flask_session_captcha import FlaskSessionCaptcha

class User:
    def __init__(self, name, password):
        self.user_name=name
        self.password=password

class InsecureDeserialization:
    user_list=[User("admin", "admin")]

    def CreateCaptcha(app):
        # Captcha Configuration 
        app.config["SECRET_KEY"] = uuid.uuid4() 
        app.config['CAPTCHA_ENABLE'] = True
        
        # Set 5 as character length in captcha 
        app.config['CAPTCHA_LENGTH'] = 5
        
        # Set the captcha height and width
        app.config['CAPTCHA_WIDTH'] = 160
        app.config['CAPTCHA_HEIGHT'] = 60
        #app.config['SESSION_MONGODB'] = InsecureDeserialization.mongoClient 
        app.config['SESSION_TYPE'] = 'filesystem'
        
        # Enables server session 
        Session(app) 
        
        # Initialize FlaskSessionCaptcha 
        return FlaskSessionCaptcha(app)
    
    def ValidateCaptcha(app_cfg, captcha, entry):
        if captcha.validate() or len(entry) == app_cfg['CAPTCHA_LENGTH']:
            print("match for captcha")
            print("success captcha validation")
            # redirect to succeed page
            return True, "Login Successful"
        else:
            print("fail captcha validation")
            # keep them trying if fails..
            return False, "Incorrect Captcha try sign in again."
    
    def SaveUser(username, password):
        user_new= User(username, password)
        InsecureDeserialization.user_list.append(user_new)
        return True
    
    def ValidateUser(username, password):
        for user in InsecureDeserialization.user_list:
            if user.user_name == username and user.password == password:
                return True
        
        return False