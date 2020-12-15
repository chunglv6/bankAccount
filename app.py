from flask import Flask
from flask_mongoengine import MongoEngine
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_jwt_extended import JWTManager

# from flask_user import current_user, login_required, roles_required, UserManager, UserMixin

app = Flask(__name__)
app.secret_key = "secret key"
# app.config["MONGO_URI"] = "mongodb://localhost:27017/firstAppPython"
app.config["MONGO_URI"] = "mongodb+srv://dbUser:dbUserPassword@chunglv6.tlrcv.mongodb.net/firstAppPython" \
                          "?retryWrites=true&w=majority"
app.config['JWT_SECRET_KEY'] = 'Dude!WhyShouldYouEncryptIt'
mongo = PyMongo(app)

CORS(app)
# JwtManager object
jwt = JWTManager(app)


class User:
    def __init__(self, _id, username):
        self.id = _id
        self.username = username

    def __str__(self):
        return "User(id='%s')" % self.id
