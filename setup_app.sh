#!/bin/bash

APP_DIR="$HOME/app_cdr"  # หรือแก้เป็น path ที่เก็บโปรเจกต์

echo "🛠️ Updating package lists..."
sudo apt update

echo "🐍 Installing Python 3, pip, and venv..."
sudo apt install -y python3 python3-pip python3-venv

echo "📁 Navigating to app directory: $APP_DIR"
cd "$APP_DIR" || { echo "❌ Directory $APP_DIR not found"; exit 1; }

echo "🌱 Creating virtual environment in ./venv"
python3 -m venv venv

echo "✅ Activating virtual environment"
source venv/bin/activate

echo "📦 Installing Python dependencies from requirements.txt"
pip install -r requirements.txt
