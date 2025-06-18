from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from models import db, User
from models import db, DBConfig
from werkzeug.security import check_password_hash
from sqlalchemy import create_engine, text
from datetime import datetime, timezone, timedelta
from pytz import timezone, utc
import csv
import psutil
import shutil
from io import StringIO
from flask import make_response

BANGKOK_TZ = timezone('Asia/Bangkok')
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# 🔗 เชื่อมต่อ PostgreSQL
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://csvuploader:!Q1q2w3e4r5t@localhost/csvuploader'
# MySQL or Mariadb (ใช้ pymysql เป็น driver)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://myapp:!Q1q2w3e4r5t@localhost/myapp'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('average_call_handling_by_agent'))
        else:
            return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    json_data = None
    if request.method == 'POST':
        f = request.files.get('csv_file')
        if f and f.filename.endswith('.csv'):
            import io, csv
            stream = io.StringIO(f.stream.read().decode("UTF8"), newline=None)
            reader = csv.DictReader(stream)
            json_data = list(reader)
        else:
            json_data = []

        return render_template('upload.html', username=session['username'], json_data=json_data)

    return render_template('upload.html', username=session['username'])


@app.route('/users')
def manage_users():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = User.query.all()
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
                result = connection.execute(text(f"SELECT * FROM {table} ORDER BY cdr_started_at DESC LIMIT 10"))
                columns = result.keys()
                data = [dict(row._mapping) for row in result]
        except Exception as e:
            error = str(e)

        return render_template('db_config.html', username=session['username'], config=config, data=data, columns=columns, error=error)

    # GET method แสดง config เดิม
    return render_template('db_config.html', username=session['username'], config=config)

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

    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
        from_date = (now - timedelta(days=30)).astimezone(utc)
        to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text(f"""
                SELECT * FROM {config.table}
                WHERE cdr_started_at >= :from_date AND cdr_started_at <= :to_date
                ORDER BY cdr_started_at DESC;
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT source_entity_type, COUNT(*) AS count
                FROM cdroutput
                WHERE cdr_started_at >= :from_date
                  AND cdr_started_at <= :to_date
                GROUP BY source_entity_type
                ORDER BY count DESC;
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
    page_title="Internal Call"
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT *
                FROM cdroutput
                WHERE source_entity_type = 'extension'
                  AND destination_entity_type = 'extension'
                  AND cdr_started_at >= :from_date
                  AND cdr_started_at <= :to_date
                ORDER BY cdr_started_at DESC;
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


@app.route('/outbound_calls')
def outbound_calls():
    page_title="Outbound Call"
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT *
                FROM cdroutput
                WHERE source_entity_type = 'extension'
                  AND destination_entity_type = 'outbound_rule'
                  AND cdr_started_at >= :from_date
                  AND cdr_started_at <= :to_date
                ORDER BY cdr_started_at DESC;
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
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    
    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT *
                FROM cdroutput
                WHERE source_entity_type = 'external_line'
                  AND cdr_started_at >= :from_date
                  AND cdr_started_at <= :to_date
                ORDER BY cdr_started_at DESC;
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


@app.route('/average_call_handling_by_agent')
def average_call_handling_by_agent():
    page_title="AVG Call Handling"
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    source_participant_name AS agent_name,
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS average_handling_time_seconds
                FROM cdroutput
                WHERE (source_entity_type = 'extension' OR destination_entity_type = 'extension')
                    AND cdr_answered_at IS NOT NULL
                    AND cdr_ended_at IS NOT NULL
                    AND cdr_answered_at >= :from_date AND cdr_answered_at <= :to_date
                GROUP BY agent_name
                ORDER BY average_handling_time_seconds;
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


@app.route('/call_handled_per_agent')
def call_handled_per_agent():
    page_title="Agent Call Handled"
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    source_participant_name AS agent_name,
                    COUNT(DISTINCT call_history_id) AS calls_handled
                FROM cdroutput
                WHERE (source_entity_type = 'extension' OR destination_entity_type = 'extension')
                    AND cdr_answered_at IS NOT NULL
                    AND cdr_answered_at >= :from_date AND cdr_answered_at <= :to_date
                GROUP BY agent_name
                ORDER BY calls_handled DESC;
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                WITH AgentCalls AS (
                    SELECT
                        source_participant_name AS agent_name,
                        cdr_started_at,
                        cdr_ended_at,
                        cdr_answered_at,
                        CASE
                            WHEN cdr_answered_at IS NOT NULL THEN 1 ELSE 0
                        END AS was_answered
                    FROM cdroutput
                    WHERE (source_entity_type = 'extension' OR destination_entity_type = 'extension')
                        AND cdr_started_at >= :from_date
                        AND cdr_started_at <= :to_date
                )
                SELECT
                    agent_name,
                    SUM(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_started_at))) AS total_call_time_seconds,
                    SUM(CASE WHEN was_answered = 1 THEN EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at)) ELSE 0 END) AS total_talk_time_seconds,
                    (
                        SUM(CASE WHEN was_answered = 1 THEN EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at)) ELSE 0 END) /
                        NULLIF(SUM(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_started_at))), 0)
                    ) AS utilization_rate
                FROM AgentCalls
                GROUP BY agent_name
                ORDER BY utilization_rate DESC;
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
    date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

    # รับวันจาก query string
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")
    try:
        if from_date_str:
            # ตีความวันที่ว่าเป็นเวลาไทย แล้วแปลงเป็น UTC
            from_date_local = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT c.*
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    destination_dn_name AS queue_name,
                    COUNT(DISTINCT call_history_id) AS calls_handled
                FROM cdroutput
                WHERE destination_entity_type = 'queue'
                  AND cdr_answered_at IS NOT NULL
                  AND cdr_started_at >= :from_date
                  AND cdr_started_at <= :to_date
                GROUP BY destination_dn_name
                ORDER BY calls_handled DESC;
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
    page_title="AVG Time Before Answered"
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    destination_dn_name AS queue_name,
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS average_talk_time_seconds
                FROM cdroutput
                WHERE destination_entity_type = 'queue'
                  AND cdr_answered_at IS NOT NULL
                  AND cdr_ended_at IS NOT NULL
                  AND cdr_started_at >= :from_date
                  AND cdr_started_at <= :to_date
                GROUP BY destination_dn_name
                ORDER BY average_talk_time_seconds DESC;
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    destination_dn_name AS queue_name,
                    COUNT(DISTINCT call_history_id) AS abandoned_calls
                FROM cdroutput
                WHERE destination_entity_type = 'queue'
                    AND source_entity_type = 'external_line'
                    AND termination_reason = 'src_participant_terminated'
                    AND cdr_started_at >= :from_date
                    AND cdr_started_at <= :to_date
                GROUP BY destination_dn_name
                ORDER BY abandoned_calls DESC;
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    c2.call_history_id,
                    c1.source_participant_name AS original_caller,
                    c1.destination_participant_name AS original_destination,
                    c2.destination_dn_name AS transferred_queue
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
    page_title="AVG Duration Answered External Call"
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT 
                    AVG(EXTRACT(EPOCH FROM (cdr_ended_at - cdr_answered_at))) AS average_duration_seconds
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT
                    call_history_id,
                    source_dn_number,
                    destination_dn_number,
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        # ใช้เวลาเทียบกับฟิลด์ cdr_started_at หรือฟิลด์อื่นที่เหมาะสม
        query = """
            SELECT 
                call_history_id, 
                source_participant_name, 
                destination_participant_phone_number, 
                termination_reason_details
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
    page_title="Call License Limit"
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
            from_date_local = BANGKOK_TZ.localize(datetime.now() - timedelta(days=30))

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
            from_date = (now - timedelta(days=30)).astimezone(utc)
            to_date = (now + timedelta(days=1)).astimezone(utc)

    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)

        query = """
            SELECT COUNT(*) AS license_limit_terminations
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
        db.session.commit()
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/users/<int:user_id>/delete', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # 🔒 ห้ามลบ admin
    if user.username == 'admin':
        flash('ไม่สามารถลบ admin ได้', 'danger')
        return redirect(url_for('manage_users'))

    # ✅ ลบผู้ใช้
    db.session.delete(user)
    db.session.commit()

    flash(f'ลบผู้ใช้ {user.username} แล้ว', 'success')
    return redirect(url_for('manage_users'))


# Dashboard
# def get_dashboard_data(from_date, to_date):
#     config = DBConfig.query.first()
#     if not config:
#         raise Exception("ยังไม่มีการตั้งค่า database")

#     conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
#     engine = create_engine(conn_str)
#     date_columns = ['cdr_started_at', 'cdr_answered_at', 'cdr_ended_at']

#     dashboard_data = {}

#     with engine.connect() as connection:
        
#         inbound_result = connection.execute(text("""
#                 SELECT *
#                 FROM cdroutput
#                 WHERE source_entity_type = 'external_line'
#                   AND cdr_started_at >= :from_date
#                   AND cdr_started_at <= :to_date
#                 ORDER BY cdr_started_at DESC;
#         """), {"from_date": from_date, "to_date": to_date}).mappings()

#         inbound_rows = [dict(row) for row in inbound_result]
        
#         for row in inbound_rows:
#             for col in date_columns:
#                 if col in row and isinstance(row[col], datetime):
#                     row[col] = row[col].astimezone(BANGKOK_TZ)

#         dashboard_data['inbound_data'] = inbound_rows
#         dashboard_data['inbound_count'] = len(inbound_rows)

        
#         outbound_result = connection.execute(text("""
#                 SELECT *
#                 FROM cdroutput
#                 WHERE destination_entity_type = 'external_line'
#                 AND cdr_started_at >= :from_date
#                 AND cdr_started_at <= :to_date
#         """), {"from_date": from_date, "to_date": to_date}).mappings()

#         outbound_rows = [dict(row) for row in outbound_result]
        
#         for row in outbound_rows:
#             for col in date_columns:
#                 if col in row and isinstance(row[col], datetime):
#                     row[col] = row[col].astimezone(BANGKOK_TZ)

#         dashboard_data['outbound_data'] = inbound_rows
#         dashboard_data['outbound_count'] = len(outbound_rows)

        
#         internal_result = connection.execute(text("""
#                 SELECT *
#                 FROM cdroutput
#                 WHERE source_entity_type = 'extension'
#                   AND destination_entity_type = 'extension'
#                   AND cdr_started_at >= :from_date
#                   AND cdr_started_at <= :to_date
#                 ORDER BY cdr_started_at DESC;
#         """), {"from_date": from_date, "to_date": to_date}).mappings()

#         internal_rows = [dict(row) for row in internal_result]
        
#         for row in internal_rows:
#             for col in date_columns:
#                 if col in row and isinstance(row[col], datetime):
#                     row[col] = row[col].astimezone(BANGKOK_TZ)

#         dashboard_data['internal_data'] = internal_rows
#         dashboard_data['internal_count'] = len(internal_rows)

#     return dashboard_data


def get_dashboard_data(from_date, to_date):
    config = DBConfig.query.first()
    if not config:
        raise Exception("ยังไม่มีการตั้งค่า database")

    # 🔄 แปลง from/to เป็น timezone aware และแปลงเป็น UTC
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
            SELECT * FROM cdroutput
            WHERE source_entity_type = 'external_line'
              AND cdr_started_at >= :from_date
              AND cdr_started_at < :to_date
            ORDER BY cdr_started_at DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        inbound_rows = [dict(row) for row in inbound_result]
        for row in inbound_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['inbound_data'] = inbound_rows
        dashboard_data['inbound_count'] = len(inbound_rows)

        # Outbound
        outbound_result = connection.execute(text("""
            SELECT * FROM cdroutput
            WHERE destination_entity_type = 'external_line'
              AND cdr_started_at >= :from_date
              AND cdr_started_at < :to_date;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        outbound_rows = [dict(row) for row in outbound_result]
        for row in outbound_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['outbound_data'] = outbound_rows
        dashboard_data['outbound_count'] = len(outbound_rows)

        # Internal
        internal_result = connection.execute(text("""
            SELECT * FROM cdroutput
            WHERE source_entity_type = 'extension'
              AND destination_entity_type = 'extension'
              AND cdr_started_at >= :from_date
              AND cdr_started_at < :to_date
            ORDER BY cdr_started_at DESC;
        """), {"from_date": from_date_utc, "to_date": to_date_utc}).mappings()

        internal_rows = [dict(row) for row in internal_result]
        for row in internal_rows:
            for col in date_columns:
                if col in row and isinstance(row[col], datetime):
                    row[col] = row[col].replace(tzinfo=utc).astimezone(BANGKOK_TZ)

        dashboard_data['internal_data'] = internal_rows
        dashboard_data['internal_count'] = len(internal_rows)

    return dashboard_data




# @app.route('/dashboard')
# def dashboard():
    
#     from_date = datetime.now(BANGKOK_TZ) - timedelta(days=30)
#     to_date = datetime.now(BANGKOK_TZ) + timedelta(days=1)

#     try:
#         print("Before get_dashboard_data()")
#         data = get_dashboard_data(from_date, to_date)
#         print("After get_dashboard_data()")

#         return render_template("dashboard.html",
#             inbound_count=data.get('inbound_count', 0),
#             outbound_count=data.get('outbound_count', 0),
#             internal_count=data.get('internal_count', 0)
            
#         )
#     except Exception as e:
#         return render_template("dashboard.html", error=str(e))


@app.route('/dashboard')
def dashboard():
    from_date_str = request.args.get("from_date")
    to_date_str = request.args.get("to_date")

    try:
        # ✅ กรณีมีการส่งวันที่เข้ามา
        if from_date_str:
            from_date = BANGKOK_TZ.localize(datetime.strptime(from_date_str, "%Y-%m-%d"))
        else:
            from_date = datetime.now(BANGKOK_TZ) - timedelta(days=30)

        if to_date_str:
            # +1 day เพื่อรวมทั้งวัน เช่น 2025-06-17 → ถึง 2025-06-18 00:00
            to_date = BANGKOK_TZ.localize(datetime.strptime(to_date_str, "%Y-%m-%d")) + timedelta(days=1)
        else:
            to_date = datetime.now(BANGKOK_TZ) + timedelta(days=1)

        data = get_dashboard_data(from_date, to_date)

        return render_template("dashboard.html",
            inbound_count=data.get('inbound_count', 0),
            outbound_count=data.get('outbound_count', 0),
            internal_count=data.get('internal_count', 0)
        )

    except Exception as e:
        return render_template("dashboard.html", error=str(e))



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=1881)



