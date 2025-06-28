from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Text
import json
from datetime import datetime
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')


    name = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    email = db.Column(db.String(120))
    team = db.Column(db.String(100))
    profile_image = db.Column(db.String(120))
    menu_permissions = db.Column(Text, default='[]')
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, nullable=True)

    def __init__(self, username, password, role='viewer'):
        self.username = username
        self.password = generate_password_hash(password)
        self.role = role

class DBConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(100))
    port = db.Column(db.Integer)
    dbname = db.Column(db.String(100))
    user = db.Column(db.String(100))
    password = db.Column(db.String(100))
    table = db.Column(db.String(100))

class SMTPConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(255), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    smtp_user = db.Column(db.String(255), nullable=False)
    smtp_password = db.Column(db.String(255), nullable=False)
    use_tls = db.Column(db.Boolean, default=True)
    use_ssl = db.Column(db.Boolean, default=False)