from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import pymongo

app = Flask(__name__)
app.config['SECRET_KEY'] = '8946d71d0200e86083be400cb72e4700'
app.config['UPLOAD_FOLDER']='/static/profile_pics/'

crypt = Bcrypt(app)
# login_mgr = LoginManager(app)
# login_mgr.login_view = 'login'
# login_mgr.login_message_category = 'info'

connection = pymongo.MongoClient("mongodb://localhost:27017/")
db = connection["Supermarket_Database"]
Users = db["Users"]
# Posts = db["Posts"]
Carts = db["Carts"]
Products = db["Products"]
Customer_Cart = db["Customer_Cart"]
Billing = db["Billing"]

from project import routes