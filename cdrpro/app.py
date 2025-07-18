from flask import Flask, render_template, send_from_directory, request, jsonify, send_file, abort, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf import CSRFProtect
from models import db, User, DBConfig, SMTPConfig, SystemConfig, CSATLog, CampaignCall, CampaignMessage, Knowledge
from werkzeug.security import check_password_hash
from sqlalchemy import create_engine, text
from datetime import datetime, timezone, timedelta
from pytz import timezone, utc
from flask import g
from collections import defaultdict
from rapidfuzz import fuzz
import google.generativeai as genai
import google.auth
from google.oauth2 import service_account
import csv
import psutil
import shutil
import smtplib
import json
import pyotp
import requests
import re
from urllib.parse import quote
from io import StringIO
from flask import make_response
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
import logging
from logging.handlers import RotatingFileHandler
load_dotenv()
BANGKOK_TZ = timezone('Asia/Bangkok')

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback_if_missing")

if not os.path.exists('logs'):
    os.mkdir('logs')

file_handler = RotatingFileHandler('logs/cdrpro.log', maxBytes=10240, backupCount=5)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s'))

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO) 


csrf = CSRFProtect(app)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


UPLOAD_FOLDER_CREDENTIALS = 'credentials'
ALLOWED_CREDENTIALS_EXTENSIONS = {'json'}
os.makedirs(UPLOAD_FOLDER_CREDENTIALS, exist_ok=True)
app.config['UPLOAD_FOLDER_CREDENTIALS'] = UPLOAD_FOLDER_CREDENTIALS
app.config['ALLOWED_CREDENTIALS_EXTENSIONS'] = ALLOWED_CREDENTIALS_EXTENSIONS

credential_path = os.path.join(app.config['UPLOAD_FOLDER_CREDENTIALS'], "service_account.json")
if os.path.exists(credential_path):
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credential_path
else:
    app.logger.error(f"Service account credential file not found at {credential_path}")

genai.configure()
model = genai.GenerativeModel("gemini-pro")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_credentials_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_CREDENTIALS_EXTENSIONS']



app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://myapp:!Q1q2w3e4r5t@localhost/myapp'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)




@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET'])
def login_form():
    if 'username' in request.args or 'password' in request.args:
        return "Method Not Allowed", 405
    form = LoginForm()
    return render_template('login.html', form=form)


@app.route('/login', methods=['POST'])
def login():
    
    MAX_FAILED_ATTEMPTS = SystemConfig.get("MAX_FAILED_ATTEMPTS", 3, int)
    LOCKOUT_TIME_MINUTES = SystemConfig.get("LOCKOUT_TIME_MINUTES", 5, int)
    
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data


        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return render_template('login.html', form=form, error='Invalid username format'), 401

        user = User.query.filter_by(username=username).first()

        
        if user:
            
            if user.lockout_until and user.lockout_until > datetime.utcnow():
                remaining = (user.lockout_until - datetime.utcnow()).seconds
                return render_template('login.html', form=form, error=f'บัญชีถูกล็อกชั่วคราว โปรดลองอีกครั้งใน {remaining} วินาที')

            
            if check_password_hash(user.password, password):
                
                user.failed_login_attempts = 0
                user.lockout_until = None
                db.session.commit()

                session['pre_mfa_user_id'] = user.id
                session['username'] = user.username

                if user.mfa_enabled:
                    if not user.mfa_secret:
                        return redirect(url_for('setup_mfa'))
                    else:
                        return redirect(url_for('verify_mfa'))

                user.last_login = datetime.utcnow()
                db.session.commit()

                session['user_id'] = user.id
                return redirect(url_for('dashboard'))

            else:
                
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                    user.lockout_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_TIME_MINUTES)
                user.last_failed_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
                user.last_failed_platform = request.user_agent.platform
                db.session.commit()
                if user.lockout_until:
                    return render_template('login.html', form=form, error=f'ล็อกอินผิดเกิน {MAX_FAILED_ATTEMPTS} ครั้ง บัญชีถูกล็อก {LOCKOUT_TIME_MINUTES} นาที')
                else:
                    return render_template('login.html', form=form, error='Invalid credentials')

        else:
            return render_template('login.html', form=form, error='Invalid credentials')

    return render_template('login.html', form=form)



@app.route('/setup_mfa', methods=['GET', 'POST'])
def setup_mfa():
    user_id = session.get('pre_mfa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    
    secret = session.get('temp_mfa_secret')
    if not secret:
        secret = pyotp.random_base32()
        session['temp_mfa_secret'] = secret

    totp = pyotp.TOTP(secret)
    qr_uri = totp.provisioning_uri(name=user.username, issuer_name="CDRPro")

    if request.method == 'POST':
        token = request.form['token']
        if totp.verify(token):
            
            user.mfa_secret = secret
            db.session.commit()

            
            session.pop('temp_mfa_secret', None)
            session['user_id'] = user.id 
            return redirect(url_for('consent'))
        else:
            return render_template('setup_mfa.html', error="Invalid code", qr_uri=qr_uri)

    return render_template('setup_mfa.html', qr_uri=qr_uri)



@app.route('/verify_mfa', methods=['GET', 'POST'])
def verify_mfa():
    user_id = session.get('pre_mfa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get_or_404(user_id)
    totp = pyotp.TOTP(user.mfa_secret)

    if request.method == 'POST':
        token = request.form.get('token')
        if totp.verify(token):

            session['user_id'] = user.id
            session.pop('pre_mfa_user_id', None)
            user.last_login = datetime.utcnow()
            db.session.commit()

            if not user.consent_accepted:
                return redirect(url_for('consent'))

            return redirect(url_for('dashboard'))

        else:
            return render_template('verify_mfa.html', error="Invalid OTP")

    return render_template('verify_mfa.html')


@app.route('/consent', methods=['GET', 'POST'])
def consent():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        user.consent_accepted = True
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('consent.html', user=user)


@app.route('/blocked_users')
def blocked_users():
    users = User.query.filter(
        User.lockout_until != None,
        User.lockout_until > datetime.utcnow()
    ).all()

    for user in users:
        if user.lockout_until:
            
            if user.lockout_until.tzinfo is None:
                user.lockout_until = user.lockout_until.replace(tzinfo=utc)
            
            user.lockout_until_bkk = user.lockout_until.astimezone(BANGKOK_TZ)
        else:
            user.lockout_until_bkk = None

    return render_template('blocked_users.html', users=users)

@app.route('/unlock_user/<int:user_id>', methods=['POST'])
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.failed_login_attempts = 0
    user.lockout_until = None
    user.last_failed_ip = None
    user.last_failed_platform = None
    db.session.commit()
    flash(f'ปลดล็อกผู้ใช้ {user.username} เรียบร้อยแล้ว', 'success')
    return redirect(url_for('blocked_users'))



@app.route('/users')
def manage_users():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = User.query.all()

    for user in users:
        if user.last_login:
            user.last_login = utc.localize(user.last_login)
            user.last_login_local = user.last_login.astimezone(BANGKOK_TZ)
        else:
            user.last_login_local = None
    return render_template('users.html', users=users)


@app.route('/db_config', methods=['GET', 'POST'])
def db_config():
    if 'username' not in session:
        return redirect(url_for('login'))

    error = None
    config = DBConfig.query.first()  # ดึง config ตัวแรก (ถ้ามี)

    if request.method == 'POST':
        host = request.form['host']
        port = int(request.form['port'])
        dbname = request.form['dbname']
        user = request.form['user']
        password = request.form['password']
        table = request.form['table']

        # บันทึกหรือแก้ไข config
        if config:
            config.host = host
            config.port = port
            config.dbname = dbname
            config.user = user
            config.password = password
            config.table = table
        else:
            config = DBConfig(host=host, port=port, dbname=dbname, user=user, password=password, table=table)
            db.session.add(config)
        db.session.commit()

        # ทดสอบเชื่อมต่อและโหลดข้อมูล
        data = []
        columns = []
        try:
            conn_str = f'postgresql://{user}:{password}@{host}:{port}/{dbname}'
            engine = create_engine(conn_str)
            with engine.connect() as connection:
                result = connection.execute(text(f"SELECT * FROM {table} LIMIT 20"))
                columns = result.keys()
                data = [dict(row._mapping) for row in result]
        except Exception as e:
            error = str(e)

        return render_template('db_config.html', username=session['username'], config=config, data=data, columns=columns, error=error)

    # GET method แสดง config เดิม
    return render_template('db_config.html', username=session['username'], config=config)

@app.route('/smtp_config', methods=['GET', 'POST'])
def smtp_config():
    if 'username' not in session:
        return redirect(url_for('login'))

    error = None
    config = SMTPConfig.query.first()  # Load existing config if any
    error = None
    success = None

    if request.method == 'POST':
        smtp_server = request.form['smtp_server']
        smtp_port = int(request.form['smtp_port'])
        smtp_user = request.form['smtp_user']
        smtp_password = request.form['smtp_password']
        use_tls = 'use_tls' in request.form
        use_ssl = 'use_ssl' in request.form
        test_email_to = request.form.get('test_email_to')
        action = request.form.get('action')

        if config:
            config.smtp_server = smtp_server
            config.smtp_port = smtp_port
            config.smtp_user = smtp_user
            config.smtp_password = smtp_password
            config.use_tls = use_tls
            config.use_ssl = use_ssl
        else:
            config = SMTPConfig(
                smtp_server=smtp_server,
                smtp_port=smtp_port,
                smtp_user=smtp_user,
                smtp_password=smtp_password,
                use_tls=use_tls,
                use_ssl=use_ssl
            )
            db.session.add(config)
        db.session.commit()

        # ถ้ากด Save
        if action == 'save':
            db.session.commit()
            success = "Configuration saved."

        # ถ้ากด Test
        elif action == 'test':
            ok, message = send_test_email(config, test_email_to)
            if ok:
                success = message
            else:
                error = f"SMTP Test Failed: {message}"

    return render_template("smtp_config.html", config=config, error=error, success=success, username=session['username'])


def send_test_email(config, to_email):
    try:
        server = smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=10)
        if config.use_tls:
            server.starttls()
        server.login(config.smtp_user, config.smtp_password)

        msg = MIMEText("This is a test email from your SMTP configuration.")
        msg["Subject"] = "CDRPro SMTP Test Email"
        msg["From"] = config.smtp_user
        msg["To"] = to_email

        server.sendmail(config.smtp_user, [to_email], msg.as_string())
        server.quit()

        return True, f"Test email sent successfully to {to_email}"

    except Exception as e:
        return False, str(e)

@app.route('/system_config', methods=['GET', 'POST'])
def system_config():
    if request.method == 'POST':
        SystemConfig.set("MAX_FAILED_ATTEMPTS", request.form['max_attempts'])
        SystemConfig.set("LOCKOUT_TIME_MINUTES", request.form['lockout_minutes'])
        SystemConfig.set("API_TOKEN", request.form['api_token'])
        SystemConfig.set("RECORDING_PATH", request.form['recording_path'])
        SystemConfig.set("TCX_URL", request.form['tcx_url'])
        SystemConfig.set("TCX_TOKEN_URL", request.form['tcx_token_url'])
        SystemConfig.set("TCX_CLIENT_SECRET", request.form['tcx_client_secret'])
        SystemConfig.set("TCX_GRANT_TYPE", request.form['tcx_grant_type'])
        SystemConfig.set("TCX_CLIENT_ID", request.form['tcx_client_id'])
        SystemConfig.set("TCX_CALL_CONTROL_URL", request.form['tcx_call_control_url'])
        SystemConfig.set("TCX_MAKECALL_PATH", request.form['tcx_makecall_path'])



        flash('Saved successfully', 'success')
        return redirect(url_for('system_config'))

    return render_template('system_config.html', 
        max_attempts=SystemConfig.get("MAX_FAILED_ATTEMPTS", 3),
        lockout_minutes=SystemConfig.get("LOCKOUT_TIME_MINUTES", 5),
        api_token=SystemConfig.get("API_TOKEN", ""),
        recording_path=SystemConfig.get("RECORDING_PATH", ""),
        tcx_url = SystemConfig.get("TCX_URL", ""),
        tcx_token_url = SystemConfig.get("TCX_TOKEN_URL", ""),
        tcx_client_secret = SystemConfig.get("TCX_CLIENT_SECRET", ""),
        tcx_grant_type = SystemConfig.get("TCX_GRANT_TYPE", ""),
        tcx_client_id = SystemConfig.get("TCX_CLIENT_ID", ""),
        tcx_call_control_url = SystemConfig.get("TCX_CALL_CONTROL_URL", ""),
        tcx_makecall_path = SystemConfig.get("TCX_MAKECALL_PATH", "")
    )



@app.route('/cdr_data')
def cdr_data():
    page_title="Call Detail Record"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database กรุณาตั้งค่าในเมนู Database Settings", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")

    # รับค่า filter เพิ่มเติม
    filters = {
        "source_dn_number": request.args.get("from_extension"),
        "source_dn_name": request.args.get("from_agent"),
        "source_participant_group_name": request.args.get("from_group"),
        "destination_dn_number": request.args.get("to_extension"),
        "destination_dn_name": request.args.get("to_agent"),
        "destination_participant_group_name": request.args.get("to_group"),
        "source_participant_phone_number": request.args.get("from_number"),
        "destination_participant_phone_number": request.args.get("to_number")
    }

    try:
        if from_date_str:
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)

    except ValueError:
        error = "Invalid date format"
        now = BANGKOK_TZ.localize(datetime.now())
        from_date = (now - timedelta(days=7)).astimezone(utc)
        to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        where_clauses = ["cdr_started_at >= :from_date", "cdr_started_at <= :to_date"]
        params = {"from_date": from_date, "to_date": to_date}

        for field, value in filters.items():
            if value:
                where_clauses.append(f"{field} ILIKE :{field}")
                params[field] = f"%{value}%"

        where_sql = " AND ".join(where_clauses)

        with engine.connect() as connection:
            result = connection.execute(text(f"""
                SELECT * FROM cdroutput
                WHERE {where_sql}
                ORDER BY cdr_started_at DESC;
            """), params)

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report_filter.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )



@app.route('/count_call_by_type')
def count_call_by_type():
    page_title="Call Type Report"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT source_entity_type AS "Type", COUNT(*) AS "Count"
                FROM cdroutput
                WHERE cdr_started_at >= :from_date
                AND cdr_started_at <= :to_date
                GROUP BY source_entity_type
                ORDER BY "Count" DESC;
            """), {"from_date": from_date, "to_date": to_date})

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )


@app.route('/internal_calls')
def internal_calls():
    page_title = "Internal Call"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['Start', 'Answered', 'End']

    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")

    filters = {
        "source_dn_number": request.args.get("from_extension"),
        "source_dn_name": request.args.get("from_agent"),
        "source_participant_group_name": request.args.get("from_group"),
        "destination_dn_number": request.args.get("to_extension"),
        "destination_dn_name": request.args.get("to_agent"),
        "destination_participant_group_name": request.args.get("to_group"),
        "source_participant_phone_number": request.args.get("from_number"),
        "destination_participant_phone_number": request.args.get("to_number")
    }

    try:
        if from_date_str:
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)

    except ValueError:
        error = "Invalid date format"
        now = BANGKOK_TZ.localize(datetime.now())
        from_date = (now - timedelta(days=7)).astimezone(utc)
        to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        where_clauses = [
            "co.source_entity_type = 'extension'",
            "co.destination_entity_type = 'extension'",
            "co.cdr_started_at >= :from_date",
            "co.cdr_started_at <= :to_date"
        ]
        params = {"from_date": from_date, "to_date": to_date}

        for field, value in filters.items():
            if value:
                where_clauses.append(f"co.{field} ILIKE :{field}")
                params[field] = f"%{value}%"

        where_sql = " AND ".join(where_clauses)

        with engine.connect() as connection:
            result = connection.execute(text(f"""
                SELECT 
                    co.source_entity_type AS "From Type",
                    co.source_dn_number AS "From Extension",
                    co.source_dn_name AS "From Agent",
                    co.source_participant_group_name AS "From Group",
                    co.destination_entity_type AS "To Type",
                    co.destination_dn_number AS "To Extension",
                    co.destination_dn_name AS "To Agent",
                    co.destination_participant_group_name AS "To Group",
                    co.termination_reason AS "Termination Reason",
                    co.cdr_started_at AS "Start",
                    co.cdr_answered_at AS "Answered",
                    co.cdr_ended_at AS "End",
                    co.call_history_id AS "Call ID",
                    cr.recording_url AS "Recording"
                FROM cdroutput co
                LEFT JOIN cdrrecordings cr 
                    ON co.cdr_id = cr.cdr_id
                    AND (
                        co.source_participant_id = cr.cdr_participant_id
                        OR co.destination_participant_id = cr.cdr_participant_id
                    )
                WHERE {where_sql}
                ORDER BY co.cdr_started_at DESC;
            """), params)

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report_filter.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )



@app.route('/outbound_calls')
def outbound_calls():
    page_title = "Outbound Call"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['Start', 'Answered', 'End']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")

    # รับค่า filter เพิ่มเติม
    filters = {
        "source_dn_number": request.args.get("from_extension"),
        "source_dn_name": request.args.get("from_agent"),
        "source_participant_group_name": request.args.get("from_group"),
        "destination_dn_number": request.args.get("to_extension"),
        "destination_dn_name": request.args.get("to_agent"),
        "destination_participant_group_name": request.args.get("to_group"),
        "source_participant_phone_number": request.args.get("from_number"),
        "destination_participant_phone_number": request.args.get("to_number")
    }

    try:
        if from_date_str:
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)

    except ValueError:
        error = "Invalid date format"
        now = BANGKOK_TZ.localize(datetime.now())
        from_date = (now - timedelta(days=7)).astimezone(utc)
        to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        where_clauses = [
            "co.source_entity_type = 'extension'",
            "co.destination_entity_type = 'external_line'",
            "co.cdr_started_at >= :from_date",
            "co.cdr_started_at <= :to_date"
        ]
        params = {"from_date": from_date, "to_date": to_date}

        for field, value in filters.items():
            if value:
                where_clauses.append(f"co.{field} ILIKE :{field}")
                params[field] = f"%{value}%"

        where_sql = " AND ".join(where_clauses)

        with engine.connect() as connection:
            result = connection.execute(text(f"""
                SELECT 
                    co.source_entity_type AS "From Type",
                    co.source_dn_number AS "From Extension",
                    co.source_dn_name AS "From Agent",
                    co.source_participant_group_name AS "From Group",
                    co.destination_entity_type AS "To Type",
                    co.destination_dn_name AS "Trunk",
                    co.destination_participant_phone_number AS "To Number",
                    co.termination_reason AS "Termination Reason",
                    co.cdr_started_at AS "Start",
                    co.cdr_answered_at AS "Answered",
                    co.cdr_ended_at AS "End",
                    co.call_history_id AS "Call ID",
                    cr.recording_url AS "Recording"
                FROM cdroutput co
                LEFT JOIN cdrrecordings cr 
                    ON co.cdr_id = cr.cdr_id
                    AND (
                        co.source_participant_id = cr.cdr_participant_id
                        OR co.destination_participant_id = cr.cdr_participant_id
                    )
                WHERE {where_sql}
                ORDER BY co.cdr_started_at DESC;
            """), params)

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report_filter.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )


@app.route('/inbound_calls')
def inbound_calls():
    page_title="Inbound Call"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['Start', 'Answered', 'End']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")

    # รับค่า filter เพิ่มเติม
    filters = {
        "source_dn_number": request.args.get("from_extension"),
        "source_dn_name": request.args.get("from_agent"),
        "source_participant_group_name": request.args.get("from_group"),
        "destination_dn_number": request.args.get("to_extension"),
        "destination_dn_name": request.args.get("to_agent"),
        "destination_participant_group_name": request.args.get("to_group"),
        "source_participant_phone_number": request.args.get("from_number"),
        "destination_participant_phone_number": request.args.get("to_number")
    }

    try:
        if from_date_str:
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)

    except ValueError:
        error = "Invalid date format"
        now = BANGKOK_TZ.localize(datetime.now())
        from_date = (now - timedelta(days=7)).astimezone(utc)
        to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        where_clauses = ["co.cdr_started_at >= :from_date", "co.cdr_started_at <= :to_date", "co.source_entity_type = 'external_line'"]
        params = {"from_date": from_date, "to_date": to_date}

        for field, value in filters.items():
            if value:
                where_clauses.append(f"co.{field} ILIKE :{field}")
                params[field] = f"%{value}%"

        where_sql = " AND ".join(where_clauses)

        with engine.connect() as connection:
            result = connection.execute(text(f"""
                SELECT 
                    co.source_entity_type AS "From Type",
                    co.source_participant_phone_number AS "From Number",
                    co.source_participant_trunk_did AS "Trunk DID",
                    co.destination_entity_type AS "To Type",
                    co.destination_dn_number AS "To Number",
                    co.destination_dn_name AS "To Name",
                    co.destination_participant_group_name AS "To Group",
                    co.termination_reason AS "Termination Reason",
                    co.cdr_started_at AS "Start",
                    co.cdr_answered_at AS "Answered",
                    co.cdr_ended_at AS "End",
                    co.call_history_id AS "Call ID",
                    cr.recording_url AS "Recording"
                FROM cdroutput co
                LEFT JOIN cdrrecordings cr 
                    ON co.cdr_id = cr.cdr_id
                    AND (
                        co.source_participant_id = cr.cdr_participant_id
                        OR co.destination_participant_id = cr.cdr_participant_id
                    )
                WHERE {where_sql}
                ORDER BY co.cdr_started_at DESC;
            """), params)

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report_filter.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )


@app.route('/average_call_handling_by_agent')
def average_call_handling_by_agent():
    page_title="Average Call Handling By Agent"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    COALESCE(inb.agent, outb.agent, intl.agent) AS "Agent",
                    inb.avg_time AS "AVG Time Inbound (s)",
                    outb.avg_time AS "AVG Time Outbound (s)",
                    intl.avg_time AS "AVG Time Internal (s)"
                FROM
                    (
                        SELECT
                            destination_dn_name AS agent,
                            AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS avg_time
                        FROM cdroutput
                        WHERE source_entity_type = 'external_line'
                        AND destination_entity_type = 'extension'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at >= :from_date AND cdr_answered_at <= :to_date
                        GROUP BY destination_dn_name
                    ) AS inb
                FULL OUTER JOIN
                    (
                        SELECT
                            source_participant_name AS agent,
                            AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS avg_time
                        FROM cdroutput
                        WHERE source_entity_type = 'extension'
                        AND destination_entity_type = 'external_line'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at >= :from_date AND cdr_answered_at <= :to_date
                        GROUP BY source_participant_name
                    ) AS outb
                ON inb.agent = outb.agent
                FULL OUTER JOIN
                    (
                        SELECT
                            source_participant_name AS agent,
                            AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS avg_time
                        FROM cdroutput
                        WHERE source_entity_type = 'extension'
                        AND destination_entity_type = 'extension'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at >= :from_date AND cdr_answered_at <= :to_date
                        GROUP BY source_participant_name
                    ) AS intl
                ON COALESCE(inb.agent, outb.agent) = intl.agent
                ORDER BY "Agent";
            """), {"from_date": from_date, "to_date": to_date})

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )

@app.route('/count_call_handling_by_agent')
def count_call_handling_by_agent():
    page_title="Count Call Handling"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    COALESCE(inb.agent, outb.agent, intl.agent) AS "Agent",
                    COALESCE(inb.call_count, 0) AS "Inbound Calls",
                    COALESCE(outb.call_count, 0) AS "Outbound Calls",
                    COALESCE(intl.call_count, 0) AS "Internal Calls"
                FROM
                    (
                        SELECT
                            destination_dn_name AS agent,
                            COUNT(*) AS call_count
                        FROM cdroutput
                        WHERE source_entity_type = 'external_line'
                        AND destination_entity_type = 'extension'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at BETWEEN :from_date AND :to_date
                        GROUP BY destination_dn_name
                    ) AS inb
                FULL OUTER JOIN
                    (
                        SELECT
                            source_participant_name AS agent,
                            COUNT(*) AS call_count
                        FROM cdroutput
                        WHERE source_entity_type = 'extension'
                        AND destination_entity_type = 'external_line'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at BETWEEN :from_date AND :to_date
                        GROUP BY source_participant_name
                    ) AS outb
                ON inb.agent = outb.agent
                FULL OUTER JOIN
                    (
                        SELECT
                            source_participant_name AS agent,
                            COUNT(*) AS call_count
                        FROM cdroutput
                        WHERE source_entity_type = 'extension'
                        AND destination_entity_type = 'extension'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at BETWEEN :from_date AND :to_date
                        GROUP BY source_participant_name
                    ) AS intl
                ON COALESCE(inb.agent, outb.agent) = intl.agent
                ORDER BY "Agent";

            """), {"from_date": from_date, "to_date": to_date})

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )



@app.route('/agent_utilization_rate')
def agent_utilization_rate():
    page_title="Agent Utilization Rate"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                WITH InboundCalls AS (
                    SELECT
                        destination_dn_name AS agent_name,
                        COUNT(*) AS total_calls_inbound,
                        SUM(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_started_at))) AS total_call_time_inbound,
                        SUM(
                            CASE
                                WHEN cdr_answered_at IS NOT NULL THEN EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))
                                ELSE 0
                            END
                        ) AS total_talk_time_inbound
                    FROM cdroutput
                    WHERE source_entity_type = 'external_line'
                    AND destination_entity_type = 'extension'
                    AND cdr_started_at BETWEEN :from_date AND :to_date
                    AND (termination_reason = 'dst_participant_terminated' OR termination_reason = 'src_participant_terminated')
                    GROUP BY destination_dn_name
                ),
                OutboundCalls AS (
                    SELECT
                        source_participant_name AS agent_name,
                        COUNT(*) AS total_calls_outbound,
                        SUM(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_started_at))) AS total_call_time_outbound,
                        SUM(
                            CASE
                                WHEN cdr_answered_at IS NOT NULL THEN EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))
                                ELSE 0
                            END
                        ) AS total_talk_time_outbound
                    FROM cdroutput
                    WHERE source_entity_type = 'extension'
                    AND destination_entity_type = 'external_line'
                    AND cdr_started_at BETWEEN :from_date AND :to_date
                    GROUP BY source_participant_name
                )

                SELECT
                    COALESCE(i.agent_name, o.agent_name) AS "Agent",

                    -- Inbound
                    COALESCE(i.total_calls_inbound, 0) AS "Total Calls Inbound",
                    COALESCE(i.total_call_time_inbound, 0) AS "Call Time Inbound",
                    COALESCE(i.total_talk_time_inbound, 0) AS "Talk Time Inbound",
                    CASE
                        WHEN COALESCE(i.total_call_time_inbound, 0) = 0 THEN 0
                        ELSE COALESCE(i.total_talk_time_inbound, 0) / NULLIF(i.total_call_time_inbound, 0)
                    END AS "Utilization Inbound",

                    -- Outbound
                    COALESCE(o.total_calls_outbound, 0) AS "Total Calls Outbound",
                    COALESCE(o.total_call_time_outbound, 0) AS "Call Time Outbound",
                    COALESCE(o.total_talk_time_outbound, 0) AS "Talk Time Outbound",
                    CASE
                        WHEN COALESCE(o.total_call_time_outbound, 0) = 0 THEN 0
                        ELSE COALESCE(o.total_talk_time_outbound, 0) / NULLIF(o.total_call_time_outbound, 0)
                    END AS "Utilization Outbound"

                FROM InboundCalls i
                FULL OUTER JOIN OutboundCalls o
                    ON i.agent_name = o.agent_name
                ORDER BY "Agent";

            """), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )


@app.route('/list_all_lost_queue_calls')
def list_all_lost_queue_calls():
    page_title="Lost Queue Call"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['Start', 'Answered', 'End']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT 
                    c.source_entity_type as "Source Type",
                    c.source_participant_phone_number as "From Number",
                    c.source_participant_trunk_did as "Trunk DID",
                    c.destination_entity_type as "To Type",
                    c.destination_dn_number as "Queue Number",
                    c.destination_dn_name as "Queue Name",
                    c.destination_participant_group_name as "To Group",
                    c.termination_reason as "Termination Reason",
                    c.cdr_started_at as "Start",
                    c.cdr_answered_at as "Answered",
                    c.cdr_ended_at as "End",
                    c.call_history_id as "Call ID",
                    (c.cdr_ended_at - c.cdr_answered_at) as "Waiting Time(s)"
                FROM public.cdroutput AS c
                WHERE c.destination_entity_type = 'queue'
                AND c.termination_reason IN ('src_participant_terminated', 'dst_participant_terminated') 
                AND c.cdr_started_at >= :from_date 
                AND c.cdr_started_at <= :to_date 
                ORDER BY c.main_call_history_id DESC, c.cdr_id DESC;
            """), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )


@app.route('/calls_handled_by_each_queue')
def calls_handled_by_each_queue():
    page_title="Queue Call Handled"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    COALESCE(queue_name, 'Unknown') AS "Queue Name",
                    SUM(calls_handled) AS "Service Calls",
                    SUM(abandoned_calls) AS "Abandoned Calls",
                    SUM(calls_handled) + SUM(abandoned_calls) AS "Total Calls"
                FROM (
                    -- Service Calls
                    SELECT
                        destination_dn_name AS queue_name,
                        COUNT(DISTINCT call_history_id) AS calls_handled,
                        0 AS abandoned_calls
                    FROM cdroutput
                    WHERE destination_entity_type = 'queue'
                    AND termination_reason NOT IN ('src_participant_terminated', 'dst_participant_terminated')
                    AND cdr_answered_at IS NOT NULL
                    AND destination_dn_name IS NOT NULL
                    AND cdr_started_at BETWEEN :from_date AND :to_date
                    GROUP BY destination_dn_name

                    UNION ALL

                    -- Abandoned Calls
                    SELECT
                        destination_dn_name AS queue_name,
                        0 AS calls_handled,
                        COUNT(DISTINCT call_history_id) AS abandoned_calls
                    FROM cdroutput
                    WHERE destination_entity_type = 'queue'
                    AND termination_reason IN ('src_participant_terminated', 'dst_participant_terminated')
                    AND destination_dn_name IS NOT NULL
                    AND cdr_started_at BETWEEN :from_date AND :to_date
                    GROUP BY destination_dn_name
                ) AS combined
                GROUP BY queue_name
                ORDER BY "Total Calls" DESC NULLS LAST;
            """), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )


@app.route('/average_time_before_agents_answered')
def average_time_before_agents_answered():
    page_title="Average Time Before Answered"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    destination_dn_name AS "Queue Name",
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS "AVG Wait Time Seconds"
                FROM cdroutput
                WHERE destination_entity_type = 'queue'
                AND cdr_answered_at IS NOT NULL
                AND cdr_ended_at IS NOT NULL
                AND cdr_started_at >= :from_date
                AND cdr_started_at <= :to_date
                GROUP BY destination_dn_name
                ORDER BY "AVG Wait Time Seconds" DESC;
            """), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )



@app.route('/terminated_before_being_answered')
def terminated_before_being_answered():
    page_title="Terminated Before Answered"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    destination_dn_name AS "Queue Name",
                    COUNT(DISTINCT call_history_id) AS "Abandoned Calls"
                FROM cdroutput
                WHERE destination_entity_type = 'queue'
                    AND source_entity_type = 'external_line'
                    AND termination_reason = 'src_participant_terminated'
                    AND cdr_started_at >= :from_date
                    AND cdr_started_at <= :to_date
                GROUP BY destination_dn_name
                ORDER BY "Abandoned Calls" DESC;
            """), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )



@app.route('/calls_transferred_to_queue')
def calls_transferred_to_queue():
    page_title="Call Transfer To Queue"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    c2.call_history_id as "Call ID",
                    c1.source_participant_name AS "Original Caller",
                    c1.destination_participant_name AS "Original Destination",
                    c2.destination_dn_name AS "Transferred Queue"
                FROM cdroutput c1
                JOIN cdroutput c2 ON c1.call_history_id = c2.call_history_id
                WHERE c1.creation_method IN ('call_init', 'route_to')
                    AND c2.creation_method = 'transfer'
                    AND c2.destination_entity_type = 'queue'
                    AND c2.base_cdr_id = c1.cdr_id
                    AND c2.cdr_started_at >= :from_date
                    AND c2.cdr_started_at <= :to_date
            """), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )



@app.route('/avg_call_duration_answered_external')
def avg_call_duration_answered_external():
    page_title="Average Duration of Answered External Outbound Calls"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT 
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS "Average Duration Seconds"
                FROM cdroutput
                WHERE source_entity_type != 'external_line'
                    AND destination_entity_type = 'external_line'
                    AND cdr_answered_at IS NOT NULL
                    AND cdr_ended_at IS NOT NULL
                    AND cdr_started_at >= :from_date
                    AND cdr_started_at <= :to_date
            """), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )


@app.route('/longest_internal_calls')
def longest_internal_calls():
    page_title="Longest Internal Call"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    call_history_id as "Call ID",
                    source_dn_number as "From Extension",
                    source_dn_name as "From Name",
                    source_participant_group_name as "From Group",
                    destination_dn_number as "To Extension",
                    destination_dn_name as "To Name",
                    destination_participant_group_name as "To Group",
                    termination_reason as "Termination Reason",
                    (cdr_ended_at - cdr_answered_at) AS duration
                FROM cdroutput
                WHERE source_entity_type != 'external_line'
                    AND destination_entity_type != 'external_line'
                    AND cdr_answered_at IS NOT NULL
                    AND cdr_ended_at IS NOT NULL
                    AND cdr_started_at >= :from_date
                    AND cdr_started_at <= :to_date
                ORDER BY duration DESC
                LIMIT 10;
            """), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = str(e)

    return render_template(
        'table_report.html',
        username=session['username'],
        data=data,
        columns=columns,
        page_title=page_title,
        error=error
    )


@app.route('/calls_no_route')
def calls_no_route():
    page_title="Outbound Failed"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        # ใช้เวลาเทียบกับฟิลด์ cdr_started_at หรือฟิลด์อื่นที่เหมาะสม
        query = """
            SELECT 
                call_history_id as "Call ID", 
                source_participant_name as "Agent" , 
                destination_participant_phone_number as "To Number", 
                termination_reason_details as "Termination Reason"
            FROM 
                cdroutput
            WHERE 
                termination_reason_details = 'no_route'
                AND cdr_started_at >= :from_date
                AND cdr_started_at <= :to_date;
        """

        with engine.connect() as connection:
            result = connection.execute(text(query), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = f"เกิดข้อผิดพลาดในการดึงข้อมูล: {e}"

    return render_template(
        'table_report.html',
        username=session.get('username'),
        data=data,
        columns=columns,
        error=error,
        page_title=page_title
    )


@app.route('/calls_license_limits')
def calls_license_limits():
    page_title="Call License Limit Terminations"
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database", 400

    data = []
    columns = []
    error = None
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=7))

        if to_date_str:
            to_date_local = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date_local = BANGKOK_TZ.localize(datetime.now()) + timedelta(days=1)

        # แปลงเป็น UTC สำหรับใช้ใน query
        from_date = from_date_local.astimezone(utc)
        to_date = to_date_local.astimezone(utc)
    
    except ValueError:
            error = "Invalid date format"
            now = BANGKOK_TZ.localize(datetime.now())
            from_date = (now - timedelta(days=7)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        query = """
            SELECT COUNT(*) AS "License Limit Terminations"
            FROM cdroutput
            WHERE termination_reason_details = 'license_limit_reached'
            AND cdr_started_at >= :from_date
            AND cdr_started_at <= :to_date;
        """

        with engine.connect() as connection:
            result = connection.execute(text(query), {
                "from_date": from_date,
                "to_date": to_date
            })

            columns = result.keys()
            rows = [dict(row._mapping) for row in result]

            
            # Convert datetime fields to Bangkok time
            for row in rows:
                for col in date_columns:
                    if col in row and isinstance(row[col], datetime):
                        row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)
            data = rows

    except Exception as e:
        error = f"เกิดข้อผิดพลาดในการดึงข้อมูล: {e}"

    return render_template(
        'table_report.html',
        username=session.get('username'),
        data=data,
        columns=columns,
        error=error,
        page_title=page_title
    )


@app.context_processor
def inject_system_utilization():
    import psutil, shutil

    try:
        cpu_usage = psutil.cpu_percent(interval=0.1)
        cpu_cores = psutil.cpu_count(logical=True)
        cpu_processes = len(psutil.pids())

        mem = psutil.virtual_memory()
        mem_total = round(mem.total / (1024 * 1024))
        mem_used = round(mem.used / (1024 * 1024))
        mem_percent = mem.percent

        disk = shutil.disk_usage("/")
        disk_total = round(disk.total / (1024**3))
        disk_used = round(disk.used / (1024**3))
        disk_percent = round((disk.used / disk.total) * 100)

        return dict(
            cpu_usage=cpu_usage,
            cpu_cores=cpu_cores,
            cpu_processes=cpu_processes,
            mem_total=mem_total,
            mem_used=mem_used,
            mem_percent=mem_percent,
            disk_total=disk_total,
            disk_used=disk_used,
            disk_percent=disk_percent
        )
    except:
        return {}

@app.before_request
def load_user():
    g.user = None
    if 'username' in session:
        g.user = User.query.filter_by(username=session['username']).first()

# @app.context_processor
# def inject_user():
#     return dict(user=g.get('user', None))

@app.context_processor
def inject_user():
    def can_view(menu_key):
        if not g.user:
            return False
        if g.user.role == 'admin':
            return True
        try:
            import json
            permissions = json.loads(g.user.menu_permissions or '[]')
            return menu_key in permissions
        except:
            return False

    return dict(user=g.get('user', None), can_view=can_view)


@app.template_filter('from_json')
def from_json_filter(s):
    import json
    try:
        return json.loads(s)
    except Exception:
        return []

@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # ตรวจสอบว่า username ซ้ำหรือไม่
        if User.query.filter_by(username=username).first():
            flash('Username นี้มีอยู่แล้ว', 'danger')
            return redirect(url_for('create_user'))

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('สร้างผู้ใช้สำเร็จ', 'success')
        return redirect(url_for('manage_users'))

    return render_template('create_user.html')

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        user.mfa_enabled = 'mfa_enabled' in request.form

        password = request.form.get('password')
        if password:
            user.password = generate_password_hash(password)

        # จัดการ menu_permissions
        permissions = request.form.getlist('menu_permissions')
        user.menu_permissions = json.dumps(permissions)

        db.session.commit()
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/users/<int:user_id>/delete', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # ห้ามลบ admin
    if user.username == 'admin':
        flash('ไม่สามารถลบ admin ได้', 'danger')
        return redirect(url_for('manage_users'))

    # ลบผู้ใช้
    db.session.delete(user)
    db.session.commit()

    flash(f'ลบผู้ใช้ {user.username} แล้ว', 'success')
    return redirect(url_for('manage_users'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return "User not found", 404

    if request.method == 'POST':
        user.name = request.form.get('name')
        user.lastname = request.form.get('lastname')
        user.email = request.form.get('email')
        user.team = request.form.get('team')

        # อัปโหลดรูปภาพ
        file = request.files.get('profile_image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            user.profile_image = filename

        db.session.commit()
        flash("Profile updated successfully.")
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)





def get_dashboard_data(from_date, to_date):
    config = DBConfig.query.first()
    if not config:
        raise Exception("ยังไม่มีการตั้งค่า database")

    # แปลง from/to เป็น timezone aware และแปลงเป็น UTC
    if from_date.tzinfo is None:
        from_date = BANGKOK_TZ.localize(from_date)
    if to_date.tzinfo is None:
        to_date = BANGKOK_TZ.localize(to_date)

    from_date_utc = from_date.astimezone(utc)
    to_date_utc = to_date.astimezone(utc)

    conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
    engine = create_engine(conn_str)
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    dashboard_data = {}

    with engine.connect() as connection:
        # Inbound
        inbound_result = connection.execute(text("""
            SELECT DISTINCT ON (call_history_id) *
            FROM cdroutput
            WHERE source_entity_type = 'external_line'
                AND cdr_started_at >= :from_date
                AND cdr_started_at <= :to_date
            ORDER BY call_history_id, cdr_started_at DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        inbound_rows = [dict(row) for row in inbound_result]
        for row in inbound_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['inbound_data'] = inbound_rows
        dashboard_data['inbound_count'] = len(inbound_rows)

        service_call_result = connection.execute(text("""
            SELECT DISTINCT ON (call_history_id) *
            FROM cdroutput
            WHERE source_entity_type = 'external_line'
                AND destination_entity_type = 'extension'
                AND cdr_answered_at IS NOT NULL
                AND cdr_started_at >= :from_date
                AND cdr_started_at <= :to_date
            ORDER BY call_history_id, cdr_started_at DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        service_call_rows = [dict(row) for row in service_call_result]
        for row in service_call_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['service_call_data'] = service_call_rows
        dashboard_data['service_call_count'] = len(service_call_rows)

        # Outbound
        outbound_result = connection.execute(text("""
            SELECT DISTINCT ON (call_history_id) *
            FROM cdroutput
            WHERE destination_entity_type = 'outbound_rule'
            AND cdr_started_at >= :from_date
            AND cdr_started_at <= :to_date
            ORDER BY call_history_id, cdr_started_at DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        outbound_rows = [dict(row) for row in outbound_result]
        for row in outbound_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['outbound_data'] = outbound_rows
        dashboard_data['outbound_count'] = len(outbound_rows)

        # Outbound Reject
        outbound_reject_result = connection.execute(text("""
            SELECT DISTINCT ON (call_history_id) *
            FROM cdroutput
            WHERE source_entity_type = 'extension'
            AND destination_entity_type = 'external_line'
            AND termination_reason = 'rejected'
            AND cdr_started_at >= :from_date
            AND cdr_started_at <= :to_date
            ORDER BY call_history_id, cdr_started_at DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        outbound_reject_rows = [dict(row) for row in outbound_reject_result]
        for row in outbound_reject_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['outbound_reject_data'] = outbound_reject_rows
        dashboard_data['outbound_reject_count'] = len(outbound_reject_rows)

        # Internal
        internal_result = connection.execute(text("""
            SELECT DISTINCT ON (call_history_id) *
            FROM cdroutput
            WHERE source_entity_type = 'extension'
            AND destination_entity_type = 'extension'
            AND cdr_started_at >= :from_date
            AND cdr_started_at <= :to_date
            ORDER BY call_history_id, cdr_started_at DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        internal_rows = [dict(row) for row in internal_result]
        for row in internal_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['internal_data'] = internal_rows
        dashboard_data['internal_count'] = len(internal_rows)

        # Abandoned
        abandoned_result = connection.execute(text("""
                SELECT c.*
                FROM public.cdroutput AS c
                WHERE c.destination_entity_type = 'queue'
                AND c.termination_reason IN ('src_participant_terminated', 'dst_participant_terminated')
                AND c.cdr_started_at >= :from_date
                AND c.cdr_started_at <= :to_date
                ORDER BY c.main_call_history_id DESC, c.cdr_id DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        abandoned_rows = [dict(row) for row in abandoned_result]
        for row in abandoned_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['abandoned_data'] = abandoned_rows
        dashboard_data['abandoned_count'] = len(abandoned_rows)
        
        #Avg Duration outbound Call
        avg_dur_outbound_calls = connection.execute(text("""
                SELECT 
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS "Average Duration Seconds"
                FROM cdroutput
                WHERE source_entity_type != 'external_line'
                    AND destination_entity_type = 'external_line'
                    AND cdr_answered_at IS NOT NULL
                    AND cdr_ended_at IS NOT NULL
                    AND cdr_started_at >= :from_date
                    AND cdr_started_at <= :to_date
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        avg_dur_outbound_calls_rows = [dict(row) for row in avg_dur_outbound_calls]
        for row in avg_dur_outbound_calls_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['avg_dur_outbound_calls_data'] = avg_dur_outbound_calls_rows

        #Avg Duration inbound Call
        avg_dur_inbound_calls = connection.execute(text("""
                SELECT 
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS "Average Duration Seconds"
                FROM cdroutput
                WHERE source_entity_type = 'external_line'
                    AND destination_entity_type = 'extension'
                    AND cdr_answered_at IS NOT NULL
                    AND cdr_ended_at IS NOT NULL
                    AND cdr_started_at >= :from_date
                    AND cdr_started_at <= :to_date
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        avg_dur_inbound_calls_rows = [dict(row) for row in avg_dur_inbound_calls]
        for row in avg_dur_inbound_calls_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['avg_dur_inbound_calls_data'] = avg_dur_inbound_calls_rows

        #Avg waiting time
        avg_waiting_time = connection.execute(text("""
                SELECT
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS "AVG Wait Time All Queues"
                FROM cdroutput
                WHERE destination_entity_type = 'queue'
                AND cdr_answered_at IS NOT NULL
                AND cdr_ended_at IS NOT NULL
                AND cdr_started_at >= :from_date
                AND cdr_started_at <= :to_date;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        avg_waiting_time_rows = [dict(row) for row in avg_waiting_time]
        for row in avg_dur_inbound_calls_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['avg_waiting_time_data'] = avg_waiting_time_rows

        #Max waiting time
        max_waiting_time = connection.execute(text("""
                SELECT
                    MAX(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS "Max Wait Time All Queues"
                FROM cdroutput
                WHERE destination_entity_type = 'queue'
                AND cdr_answered_at IS NOT NULL
                AND cdr_ended_at IS NOT NULL
                AND cdr_started_at >= :from_date
                AND cdr_started_at <= :to_date;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        max_waiting_time_rows = [dict(row) for row in max_waiting_time]
        for row in max_waiting_time_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['max_waiting_time_data'] = max_waiting_time_rows


        #total outbound time
        total_outbound_time = connection.execute(text("""
                SELECT 
                    SUM(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS "Total Outbound Seconds"
                FROM cdroutput
                WHERE source_entity_type != 'external_line'
                    AND destination_entity_type = 'external_line'
                    AND cdr_answered_at IS NOT NULL
                    AND cdr_ended_at IS NOT NULL
                    AND cdr_started_at >= :from_date
                    AND cdr_started_at <= :to_date;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        total_outbound_time_rows = [dict(row) for row in total_outbound_time]
        for row in total_outbound_time_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['total_outbound_time_data'] = total_outbound_time_rows

        #avg internal call time
        avg_internal_call_time = connection.execute(text("""
                SELECT 
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS "avg_internal_duration"
                FROM cdroutput
                WHERE source_entity_type = 'extension'
                AND destination_entity_type = 'extension'
                AND cdr_answered_at IS NOT NULL
                AND cdr_started_at BETWEEN :from_date AND :to_date;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        avg_internal_call_time_rows = [dict(row) for row in avg_internal_call_time]
        for row in avg_internal_call_time_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['avg_internal_call_time_data'] = avg_internal_call_time_rows

        #License Limit Exceeded
        license_limit_exceeded = connection.execute(text("""
                SELECT COUNT(*) AS "License Limit Exceeded"
                    FROM cdroutput
                    WHERE termination_reason_details = 'license_limit_reached'
                    AND cdr_started_at >= :from_date
                    AND cdr_started_at <= :to_date;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        license_limit_exceeded_rows = [dict(row) for row in license_limit_exceeded]
        for row in license_limit_exceeded_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['license_limit_exceeded_data'] = license_limit_exceeded_rows

        #agent_call_stats
        agent_call_stats = connection.execute(text("""
                SELECT
                    COALESCE(inb.agent, outb.agent, intl.agent) AS "Agent",
                    COALESCE(inb.call_count, 0) AS "Inbound Calls",
                    COALESCE(outb.call_count, 0) AS "Outbound Calls",
                    COALESCE(intl.call_count, 0) AS "Internal Calls",
                    COALESCE(inb.call_count, 0) + COALESCE(outb.call_count, 0) + COALESCE(intl.call_count, 0) AS "Total Calls"
                FROM
                    (
                        SELECT
                            destination_dn_name AS agent,
                            COUNT(*) AS call_count
                        FROM cdroutput
                        WHERE source_entity_type = 'external_line'
                        AND destination_entity_type = 'extension'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at BETWEEN :from_date AND :to_date
                        GROUP BY destination_dn_name
                    ) AS inb
                FULL OUTER JOIN
                    (
                        SELECT
                            source_participant_name AS agent,
                            COUNT(*) AS call_count
                        FROM cdroutput
                        WHERE source_entity_type = 'extension'
                        AND destination_entity_type = 'external_line'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at BETWEEN :from_date AND :to_date
                        GROUP BY source_participant_name
                    ) AS outb
                ON inb.agent = outb.agent
                FULL OUTER JOIN
                    (
                        SELECT
                            source_participant_name AS agent,
                            COUNT(*) AS call_count
                        FROM cdroutput
                        WHERE source_entity_type = 'extension'
                        AND destination_entity_type = 'extension'
                        AND cdr_answered_at IS NOT NULL
                        AND cdr_ended_at IS NOT NULL
                        AND cdr_answered_at BETWEEN :from_date AND :to_date
                        GROUP BY source_participant_name
                    ) AS intl
                ON COALESCE(inb.agent, outb.agent) = intl.agent
                ORDER BY "Total Calls" DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        agent_call_stats_rows = [dict(row) for row in agent_call_stats]
        for row in agent_call_stats_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['agent_call_stats_data'] = agent_call_stats_rows

        #queue_call_stats
        queue_call_stats = connection.execute(text("""
                SELECT
                    COALESCE(queue_name, 'Unknown') AS "Queue Name",
                    SUM(calls_handled) AS "Service Calls",
                    SUM(abandoned_calls) AS "Abandoned Calls",
                    SUM(calls_handled) + SUM(abandoned_calls) AS "Total Calls"
                FROM (
                    -- Service Calls
                    SELECT
                        destination_dn_name AS queue_name,
                        COUNT(DISTINCT call_history_id) AS calls_handled,
                        0 AS abandoned_calls
                    FROM cdroutput
                    WHERE destination_entity_type = 'queue'
                    AND termination_reason NOT IN ('src_participant_terminated', 'dst_participant_terminated')
                    AND cdr_answered_at IS NOT NULL
                    AND destination_dn_name IS NOT NULL
                    AND cdr_started_at BETWEEN :from_date AND :to_date
                    GROUP BY destination_dn_name

                    UNION ALL

                    -- Abandoned Calls
                    SELECT
                        destination_dn_name AS queue_name,
                        0 AS calls_handled,
                        COUNT(DISTINCT call_history_id) AS abandoned_calls
                    FROM cdroutput
                    WHERE destination_entity_type = 'queue'
                    AND termination_reason IN ('src_participant_terminated', 'dst_participant_terminated')
                    AND destination_dn_name IS NOT NULL
                    AND cdr_started_at BETWEEN :from_date AND :to_date
                    GROUP BY destination_dn_name
                ) AS combined
                GROUP BY queue_name
                ORDER BY "Total Calls" DESC NULLS LAST;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        queue_call_stats_rows = [dict(row) for row in queue_call_stats]
        for row in queue_call_stats_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['queue_call_stats_data'] = queue_call_stats_rows

    return dashboard_data



@app.route('/dashboard')
def dashboard():
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")

    try:
        
        if from_date_str:
            from_date = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date = datetime.now(BANGKOK_TZ) - timedelta(days=7)

        if to_date_str:
            
            to_date = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date = datetime.now(BANGKOK_TZ) + timedelta(days=1)

        data = get_dashboard_data(from_date, to_date)

        return render_template("dashboard.html",
            inbound_count=data.get('inbound_count', 0),
            outbound_count=data.get('outbound_count', 0),
            internal_count=data.get('internal_count', 0),
            abandoned_count=data.get('abandoned_count', 0),
            service_call_count=data.get('service_call_count', 0),
            outbound_reject_count=data.get('outbound_reject_count', 0),
            avg_dur_outbound_calls_data=data.get('avg_dur_outbound_calls_data', 0),
            avg_dur_inbound_calls_data=data.get('avg_dur_inbound_calls_data', 0),
            avg_internal_call_time_data=data.get('avg_internal_call_time_data', 0),
            avg_waiting_time_data=data.get('avg_waiting_time_data', 0),
            max_waiting_time_data=data.get('max_waiting_time_data', 0),
            total_outbound_time_data=data.get('total_outbound_time_data', 0),
            agent_call_stats_data=data.get('agent_call_stats_data', 0),
            queue_call_stats_data=data.get('queue_call_stats_data', 0),
            license_limit_exceeded_data=data.get('license_limit_exceeded_data', 0)
        )

    except Exception as e:
        
        return render_template("dashboard.html", error=str(e))

@app.route('/api/csat', methods=['POST'])
def receive_csat():
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]
    valid_token = SystemConfig.get("API_TOKEN", "")

    if token != valid_token:
        return jsonify({"error": "Invalid token"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        new_log = CSATLog(
            number=data.get("number"),
            score=int(data.get("score", 0)),
            result=data.get("result", ""),
            extension=data.get("extension", ""),
            agent=data.get("agent", "")
        )
        db.session.add(new_log)
        db.session.commit()
        return jsonify({"message": "CSAT received"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/csat_logs')
def csat_logs():
    logs = CSATLog.query.order_by(CSATLog.received_at.desc()).all()
    return render_template('csat_logs.html', logs=logs)

@app.route('/recordings')
def recordings():
    recording_path = SystemConfig.get("RECORDING_PATH", "/var/lib/3cxpbx/Instance1/Data/Recordings")

    try:
        files = []
        for root, dirs, filenames in os.walk(recording_path):
            for filename in filenames:
                if filename.endswith('.wav') or filename.endswith('.mp3'):
                    full_path = os.path.join(root, filename)
                    relative_path = os.path.relpath(full_path, recording_path)
                    files.append(relative_path)
        return render_template('recordings.html', files=files)
    except Exception as e:
        return str(e), 500

@app.route('/recordings/play/<path:filename>')
def play_recording(filename):
    recording_path = SystemConfig.get("RECORDING_PATH", "/var/lib/3cxpbx/Instance1/Data/Recordings")
    filepath = os.path.join(recording_path, filename)
    
    if os.path.exists(filepath):
        return send_file(filepath)
    else:
        abort(404)



@app.route('/campaign/outbound', methods=['GET', 'POST'])
def campaign_outbound():
    if request.method == 'POST':
        dn = request.form['dn']
        number = request.form['number']
        message = request.form['message']
        category = request.form['category']
        sub_category = request.form['sub_category']

        new_msg = CampaignMessage(
            dn=dn,
            number=number,
            message=message,
            category=category,
            sub_category=sub_category
        )
        db.session.add(new_msg)
        db.session.commit()

        try:
            make_outbound_call(new_msg)
            flash("โทรออกสำเร็จ", "success")
        except Exception as e:
            flash(str(e), "error")

        return redirect("/campaign/outbound")

    messages = CampaignMessage.query.order_by(CampaignMessage.created_at.desc()).all()
    for message in messages:
        if message.created_at and message.created_at.tzinfo is None:
            message.created_at = message.created_at.replace(tzinfo=utc).astimezone(BANGKOK_TZ)
        if message.called_at and message.called_at.tzinfo is None:
            message.called_at = message.called_at.replace(tzinfo=utc).astimezone(BANGKOK_TZ)

    return render_template("test_campaign_outbound.html", messages=messages)

@app.route('/api/campaign_message', methods=['POST'])
def api_create_campaign_message():
    # ตรวจสอบ token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]
    valid_token = SystemConfig.get("API_TOKEN", "")
    if token != valid_token:
        return jsonify({"error": "Invalid token"}), 403

    # ตรวจสอบ JSON
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    try:
        new_message = CampaignMessage(
            dn=data.get("dn"),
            number=data.get("number"),
            message=data.get("message", ""),
            category=data.get("category", ""),
            sub_category=data.get("sub_category", "")
        )
        db.session.add(new_message)
        db.session.commit()

        try:
            make_outbound_call(new_message)
        except Exception as e:
            # call failed, but still return created
            return jsonify({
                "message": "Created but call failed",
                "error": str(e),
                "id": new_message.id
            }), 202

        return jsonify({
            "message": "Campaign message created and call success",
            "id": new_message.id
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/api/campaign_message', methods=['POST', 'GET'])
def api_campaign_message():
    #ตรวจสอบ Authorization Header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]
    valid_token = SystemConfig.get("API_TOKEN", "")
    if token != valid_token:
        return jsonify({"error": "Invalid token"}), 403

    #POST method:
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        try:
            new_message = CampaignMessage(
                dn=data.get("dn"),
                number=data.get("number"),
                message=data.get("message", ""),
                category=data.get("category", ""),
                sub_category=data.get("sub_category", "")
            )
            db.session.add(new_message)
            db.session.commit()

            try:
                # โทรออกหลังบันทึก
                make_outbound_call(new_message)
            except Exception as call_error:
                return jsonify({
                    "message": "Created but call failed",
                    "id": new_message.id,
                    "error": str(call_error)
                }), 202

            return jsonify({
                "message": "Campaign message created and call success",
                "id": new_message.id
            }), 201

        except Exception as e:
            db.session.rollback()
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    #GET method:
    if request.method == 'GET':
        dn = request.args.get("dn")
        category = request.args.get("category")
        sub_category = request.args.get("sub_category")

        query = CampaignMessage.query
        if dn:
            query = query.filter(CampaignMessage.dn == dn)
        if category:
            query = query.filter(CampaignMessage.category == category)
        if sub_category:
            query = query.filter(CampaignMessage.sub_category == sub_category)

        messages = query.order_by(CampaignMessage.created_at.desc()).all()

        return jsonify([msg.to_dict() for msg in messages]), 200



def make_outbound_call(campaign_msg: CampaignMessage):
    # ดึง config
    token_url = SystemConfig.get("TCX_TOKEN_URL")
    client_id = SystemConfig.get("TCX_CLIENT_ID")
    client_secret = SystemConfig.get("TCX_CLIENT_SECRET")
    grant_type = SystemConfig.get("TCX_GRANT_TYPE", "client_credentials")
    call_control_url = SystemConfig.get("TCX_CALL_CONTROL_URL")
    makecall_path = SystemConfig.get("TCX_MAKECALL_PATH")

    # ขอ Access Token
    token_data = {
        "grant_type": grant_type,
        "client_id": client_id,
        "client_secret": client_secret
    }

    token_headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        token_resp = requests.post(token_url, data=token_data, headers=token_headers)
        token_resp.raise_for_status()
        access_token = token_resp.json().get("access_token")
    except Exception as e:
        raise RuntimeError(f"ไม่สามารถดึง Token ได้: {str(e)}")

    # โทรออก
    call_url = f"{call_control_url}/{campaign_msg.dn}/{makecall_path}"
    call_payload = {
        "destination": campaign_msg.number,
        "timeout": 0
    }

    call_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    try:
        call_resp = requests.post(call_url, json=call_payload, headers=call_headers)
        call_resp.raise_for_status()
        campaign_msg.call_status = 'success'
    except Exception as e:
        campaign_msg.call_status = 'failed'
        raise RuntimeError(f"โทรไม่สำเร็จ: {str(e)}")
    finally:
        campaign_msg.called_at = datetime.utcnow()
        db.session.commit()


@app.route('/campaign/upload', methods=['GET', 'POST'])
def upload_campaign():
    if request.method == 'POST':
        file = request.files['file']
        if not file or not file.filename.endswith('.csv'):
            flash("กรุณาเลือกไฟล์ CSV ที่ถูกต้อง", "danger")
            return redirect('/campaign/upload')

        stream = StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)

        for row in reader:
            call = CampaignCall(
                name=row.get('name'),
                phone_number=row.get('phone_number'),
                queue=row.get('queue'),
            )
            db.session.add(call)
        db.session.commit()
        flash("อัปโหลดข้อมูลแคมเปญเรียบร้อย", "success")

    # โหลด leads ทั้งหมด
    leads = CampaignCall.query.order_by(CampaignCall.id.desc()).all()

    # แปลง timezone ของ created_at และ called_at เป็น Asia/Bangkok
    for lead in leads:
        if lead.created_at and lead.created_at.tzinfo is None:
            lead.created_at = lead.created_at.replace(tzinfo=utc).astimezone(BANGKOK_TZ)
        if lead.called_at and lead.called_at.tzinfo is None:
            lead.called_at = lead.called_at.replace(tzinfo=utc).astimezone(BANGKOK_TZ)

    campaign_names = sorted(set([lead.name for lead in leads if lead.name]))

    campaign_summary = {}
    for name in campaign_names:
        calls = [l for l in leads if l.name == name]
        success = sum(1 for c in calls if c.call_status == 'success')
        failed = sum(1 for c in calls if c.call_status == 'failed')
        campaign_summary[name] = {'success': success, 'failed': failed}

    return render_template(
        'upload_campaign.html',
        leads=leads,
        campaign_names=campaign_names,
        campaign_summary=campaign_summary
    )


@app.route('/download/template')
def download_template():
    return send_from_directory(
        directory='static/templates',
        path='campaign_template.csv',
        as_attachment=True
    )

@app.route('/campaign/launch_bulk', methods=['POST'])
def campaign_launch_bulk():
    selected_campaigns = request.form.getlist("campaign_names")

    if not selected_campaigns:
        flash("กรุณาเลือกชื่อแคมเปญอย่างน้อยหนึ่งรายการ", "warning")
        return redirect("/campaign/upload")

    # ดึง config
    token_url = SystemConfig.get("TCX_TOKEN_URL")
    client_id = SystemConfig.get("TCX_CLIENT_ID")
    client_secret = SystemConfig.get("TCX_CLIENT_SECRET")
    grant_type = SystemConfig.get("TCX_GRANT_TYPE", "client_credentials")
    call_control_url = SystemConfig.get("TCX_CALL_CONTROL_URL")
    makecall_path = SystemConfig.get("TCX_MAKECALL_PATH")

    # ขอ access token
    try:
        token_resp = requests.post(
            token_url,
            data={
                "grant_type": grant_type,
                "client_id": client_id,
                "client_secret": client_secret
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        token_resp.raise_for_status()
        access_token = token_resp.json().get("access_token")
    except Exception as e:
        session['calling_active'] = False
        flash(f"ไม่สามารถขอ Token ได้: {str(e)}", "danger")
        return redirect("/campaign/upload")

    #ดึง leads ตาม campaign
    leads = CampaignCall.query.filter(
        CampaignCall.name.in_(selected_campaigns),
        CampaignCall.call_status == None
    ).all()

    session['calling_active'] = True

    called = 0
    failed = 0

    for lead in leads:
        if not session.get('calling_active'):
            flash("หยุดการโทรแล้ว", "warning")
            break
        dn = (lead.queue or "").strip()  # ใช้ queue เป็น DN
        if not dn or not lead.phone_number:
            continue  # ข้ามถ้าไม่มีข้อมูล

        call_url = f"{call_control_url}/{dn}/{makecall_path}"
        call_payload = {
            "destination": lead.phone_number,
            "timeout": 0
        }
        call_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }

        try:
            call_resp = requests.post(call_url, json=call_payload, headers=call_headers)
            call_resp.raise_for_status()
            lead.call_status = "success"
            lead.called_at = datetime.utcnow()
            flash(f"โทรหา {lead.phone_number} สำเร็จ", "dialing")
            called += 1
        except Exception as e:
            lead.call_status = "failed"
            flash(f"โทรหา {lead.phone_number} ล้มเหลว", "dialing")
            failed += 1

        db.session.add(lead)

    db.session.commit()
    session['calling_active'] = False
    flash(f"โทรสำเร็จ {called} รายการ / ล้มเหลว {failed} รายการ", "success")
    return redirect("/campaign/upload")




@app.route('/campaign/<name>')
def campaign_detail(name):
    leads = CampaignCall.query.filter_by(name=name).order_by(CampaignCall.id.desc()).all()

    # แปลง timezone สำหรับ created_at และ called_at
    for lead in leads:
        if lead.created_at:
            if lead.created_at.tzinfo is None:
                lead.created_at = lead.created_at.replace(tzinfo=utc)
            lead.created_at = lead.created_at.astimezone(BANGKOK_TZ)

        if lead.called_at:
            if lead.called_at.tzinfo is None:
                lead.called_at = lead.called_at.replace(tzinfo=utc)
            lead.called_at = lead.called_at.astimezone(BANGKOK_TZ)

    # คำนวณ summary สำหรับแคมเปญนี้
    success = sum(1 for l in leads if l.call_status == 'success')
    failed = sum(1 for l in leads if l.call_status == 'failed')
    total = len(leads)

    return render_template(
        'campaign_detail.html',
        campaign_name=name,
        leads=leads,
        summary={'success': success, 'failed': failed, 'total': total}
    )




@app.route('/campaign/stop')
def campaign_stop():
    session['calling_active'] = False
    flash("หยุดการโทรเรียบร้อยแล้ว", "warning")
    return redirect("/campaign/upload")



@app.route('/campaign/manage')
def manage_campaigns():
    campaigns_raw = db.session.query(
        CampaignCall.name,
        db.func.max(CampaignCall.created_at).label('created_at')
    ).group_by(CampaignCall.name).order_by(db.func.max(CampaignCall.created_at).desc()).all()

    campaigns = []
    for name, created_at in campaigns_raw:
        if created_at:
            
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=utc)
            
            created_at_bkk = created_at.astimezone(BANGKOK_TZ)
        else:
            created_at_bkk = None

        campaigns.append({
            'name': name,
            'created_at': created_at_bkk
        })

    return render_template('manage_campaign.html', campaigns=campaigns)

@app.route('/campaign/delete/<name>', methods=['POST'])
def delete_campaign(name):
    
    db.session.query(CampaignCall).filter_by(name=name).delete()
    db.session.commit()
    flash(f'ลบแคมเปญ "{name}" เรียบร้อยแล้ว', 'success')
    return redirect('/campaign/manage')


@app.route('/knowledge/upload', methods=['GET', 'POST'])
def upload_knowledge():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash("กรุณากรอกชื่อกลุ่มข้อมูล", "danger")
            return redirect('/knowledge/upload')

        if 'file' not in request.files:
            flash("ไม่พบไฟล์ CSV", "danger")
            return redirect('/knowledge/upload')

        file = request.files['file']
        if not file.filename.endswith('.csv'):
            flash("กรุณาอัปโหลดเฉพาะไฟล์ .csv", "danger")
            return redirect('/knowledge/upload')

        stream = StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)

        for row in reader:
            raw_text = '; '.join([f"{k.strip()}: {v.strip()}" for k, v in row.items()])
            db.session.add(Knowledge(name=name, raw_data=raw_text))

        db.session.commit()
        flash("อัปโหลดข้อมูลสำเร็จ", "success")
        return redirect('/knowledge/upload')

    
    records = Knowledge.query.order_by(Knowledge.created_at.desc()).all()
    return render_template('upload_knowledge.html', records=records)

@app.route('/knowledge/manage')
def manage_knowledge():
    
    grouped_data = (
        db.session.query(
            Knowledge.name,
            db.func.count(Knowledge.id).label('record_count'),
            db.func.max(Knowledge.created_at).label('last_upload')
        )
        .group_by(Knowledge.name)
        .order_by(db.func.max(Knowledge.created_at).desc())
        .all()
    )

    return render_template('manage_knowledge.html', groups=grouped_data)

@app.route('/knowledge/group/<name>')
def view_knowledge_group(name):
    records = Knowledge.query.filter_by(name=name).order_by(Knowledge.created_at.desc()).all()
    return render_template('view_knowledge_group.html', records=records, name=name)

@app.route('/knowledge/delete_group/<string:name>', methods=['POST'])
def delete_knowledge_group(name):
    items = Knowledge.query.filter_by(name=name).all()
    if not items:
        flash(f'No records found for group: {name}', 'warning')
    else:
        for item in items:
            db.session.delete(item)
        db.session.commit()
        flash(f'Deleted all knowledge in group: {name}', 'success')
    return redirect(url_for('manage_knowledge'))


@app.route('/api/knowledge', methods=['GET'])
def api_knowledge_search():
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]
    valid_token = SystemConfig.get("API_TOKEN", "")
    if token != valid_token:
        return jsonify({"error": "Invalid token"}), 403

    
    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify([])

    results = []
    all_knowledge = Knowledge.query.all() 
    for item in all_knowledge:
        searchable_text = f"{item.name or ''} {item.raw_data or ''}".lower()
        score = fuzz.partial_ratio(query, searchable_text)
        if score > 80:
            results.append({
                "id": item.id,
                "name": item.name,
                "raw_data": item.raw_data,
                "score": score
            })

    results.sort(key=lambda x: x["score"], reverse=True)

    return jsonify(results)

@app.route('/logout')
def logout():
        session.clear()
        return redirect(url_for('login'))

@app.route('/cdrpro/logs')
def view_logs():
    log_file = 'logs/cdrpro.log'
    if not os.path.exists(log_file):
        return "Log file not found."

    with open(log_file, 'r') as f:
        log_lines = f.readlines()[-200:]

    return render_template('logs.html', log_lines=log_lines)

def get_filtered_context(keyword):
    results = Knowledge.query.filter(Knowledge.raw_data.ilike(f"%{keyword}%")).all()
    return "\n\n".join(f"{r.name}: {r.raw_data}" for r in results)

@app.route('/upload_credentials', methods=['GET', 'POST'])
def upload_credentials():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in credentials upload')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected credentials file')
            return redirect(request.url)
        if file and allowed_credentials_file(file.filename):
            filename = secure_filename('service_account.json')
            filepath = os.path.join(app.config['UPLOAD_FOLDER_CREDENTIALS'], filename)
            file.save(filepath)
            flash('Google credentials uploaded successfully')
            return redirect(url_for('upload_credentials'))
        else:
            flash('Invalid credentials file type. Only JSON allowed.')
            return redirect(request.url)
    return render_template('upload_credentials.html')

@app.route("/ask", methods=["GET", "POST"])
def ask_ai():
    answer = ""
    keyword = ""
    prompt = ""

    if request.method == "POST":
        keyword = request.form.get("keyword")
        question = request.form.get("question")

        context = get_filtered_context(keyword)
        prompt = f"Context:\n{context}\n\nQuestion: {question}"

        try:
            response = model.generate_content(prompt)
            answer = response.text
        except Exception as e:
            app.logger.error(f"Error calling generative AI: {e}")
            answer = "เกิดข้อผิดพลาดในการเชื่อมต่อ AI กรุณาลองใหม่"

    return render_template("ask.html", answer=answer, keyword=keyword, prompt=prompt)



# @app.before_request
# def log_request_info():
#     app.logger.info(f"Request Headers: {request.headers}")
#     app.logger.info(f"Request Body: {request.get_data()}")

@app.before_request
def waf_and_log():
    
    app.logger.info(f"[WAF] Request Headers: {dict(request.headers)}")
    app.logger.info(f"[WAF] Request Body: {request.get_data(as_text=True)}")
    app.logger.info(f"[WAF] Request Args: {request.args.to_dict()}")
    app.logger.info(f"[WAF] Request Form: {request.form.to_dict()}")

    
    dangerous_patterns = [
        r"(?i)(\bor\b|\band\b).*(=|like)",   
        r"(?i)<script.*?>",                  
        r"(?i)union\s+select",               
        r"(?i)1\s*=\s*1",                    
    ]
    data_to_check = {}
    data_to_check.update(request.args.to_dict(flat=True))
    data_to_check.update(request.form.to_dict(flat=True))

    for value in data_to_check.values():
        for pattern in dangerous_patterns:
            if re.search(pattern, value):
                app.logger.warning(f"[WAF BLOCKED] Suspicious input: {value}")
                abort(403, "Blocked by WAF")

    
    user_agent = request.headers.get("User-Agent", "")
    if "sqlmap" in user_agent.lower():
        app.logger.warning(f"[WAF BLOCKED] User-Agent: {user_agent}")
        abort(403, "Blocked by WAF")

@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdnjs.cloudflare.com https://cdn.datatables.net https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.datatables.net https://unpkg.com; "
        "img-src 'self' data: https://api.qrserver.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    response.headers.pop("Server", None)
    return response


if __name__ == '__main__':

    app.run(debug=True, host='0.0.0.0', port=1881)



