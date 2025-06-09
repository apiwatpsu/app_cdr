from app import app
from models import db, User

with app.app_context():
    db.create_all()

    # เพิ่มผู้ใช้เริ่มต้น
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin123')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")
