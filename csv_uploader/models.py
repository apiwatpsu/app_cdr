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
    phone_number = db.Column(db.String(20), nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    last_failed_ip = db.Column(db.String(45), nullable=True)
    last_failed_platform = db.Column(db.String(50), nullable=True)

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

class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<SystemConfig {self.key}={self.value}>'

    @staticmethod
    def get(key, default=None, cast=str):
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            try:
                return cast(config.value)
            except:
                return default
        return default

    @staticmethod
    def set(key, value):
        config = SystemConfig.query.filter_by(key=key).first()
        if not config:
            config = SystemConfig(key=key, value=str(value))
            db.session.add(config)
        else:
            config.value = str(value)
        db.session.commit()

class CSATLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(50))
    score = db.Column(db.Integer)
    result = db.Column(db.Text)
    extension = db.Column(db.String(20))
    agent = db.Column(db.String(100))
    received_at = db.Column(db.DateTime, default=datetime.utcnow)

class CampaignCall(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    phone_number = db.Column(db.String(20))
    note = db.Column(db.Text)
    queue = db.Column(db.String(50))
    agent = db.Column(db.String(100))
    call_status = db.Column(db.String(50))
    remark = db.Column(db.Boolean, default=False)
    called_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CampaignMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dn = db.Column(db.String(20), nullable=False)
    number = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100))
    sub_category = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    call_status = db.Column(db.String(50))
    called_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "dn": self.dn,
            "number": self.number,
            "message": self.message,
            "category": self.category,
            "sub_category": self.sub_category,
            "call_status": self.call_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "called_at": self.called_at.isoformat() if self.called_at else None,
        }

class Knowledge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    raw_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



