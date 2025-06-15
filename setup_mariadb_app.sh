#!/bin/bash

# ================================
# CONFIG (คุณสามารถเปลี่ยนค่าตรงนี้ได้)
# ================================
DB_NAME="myapp"
DB_USER="myapp"
DB_PASS="!Q1q2w3e4r5t"
DB_HOST="localhost"
MYSQL_ROOT_PASSWORD="your_mariadb_root_password"  # แก้ตรงนี้ให้ตรงกับ root password MariaDB

# ================================
# สร้างคำสั่ง SQL สำหรับสร้าง DB และ User
# ================================
SQL_COMMANDS=$(cat <<EOF
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
EOF
)

# ================================
# รันคำสั่ง SQL ด้วย root (MariaDB/MySQL)
# ================================
echo "⚙️ Creating database and user on MariaDB..."
mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "${SQL_COMMANDS}"

# ================================
# แสดงผลลัพธ์
# ================================
if [ $? -eq 0 ]; then
    echo "✅ MariaDB setup complete."
    echo "Database: $DB_NAME"
    echo "User: $DB_USER"
    echo "Password: $DB_PASS"
else
    echo "❌ Failed to set up MariaDB. Please check root password or MariaDB server."
fi
