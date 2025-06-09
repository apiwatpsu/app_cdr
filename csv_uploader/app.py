from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from models import db, User
from models import db, DBConfig
from werkzeug.security import check_password_hash
from sqlalchemy import create_engine, text
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# 🔗 เชื่อมต่อ PostgreSQL
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://csvuploader:Tum0848989750@localhost/csvuploader'
# MySQL (ใช้ pymysql เป็น driver)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://myapp:Tum_0848989750@localhost/myapp'

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
            return redirect(url_for('upload'))
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
                result = connection.execute(text(f"SELECT * FROM {table} ORDER BY id LIMIT 10"))
                columns = result.keys()
                data = [dict(row._mapping) for row in result]
        except Exception as e:
            error = str(e)

        return render_template('db_config.html', username=session['username'], config=config, data=data, columns=columns, error=error)

    # GET method แสดง config เดิม
    return render_template('db_config.html', username=session['username'], config=config)

@app.route('/load_data')
def load_data():
    if 'username' not in session:
        return redirect(url_for('login'))

    config = DBConfig.query.first()
    if not config:
        return "ยังไม่มีการตั้งค่า database กรุณาตั้งค่าในเมนู Database Settings", 400

    data = []
    columns = []
    error = None
    try:
        conn_str = f'postgresql://{config.user}:{config.password}@{config.host}:{config.port}/{config.dbname}'
        engine = create_engine(conn_str)
        with engine.connect() as connection:
            result = connection.execute(text(f"SELECT * FROM {config.table} ORDER BY id LIMIT 10000"))
            columns = result.keys()
            data = [dict(row._mapping) for row in result]
    except Exception as e:
        error = str(e)

    return render_template('load_data.html', username=session['username'], data=data, columns=columns, error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# if __name__ == '__main__':
#     app.run(debug=True)
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)



