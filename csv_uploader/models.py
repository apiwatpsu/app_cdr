from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')

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