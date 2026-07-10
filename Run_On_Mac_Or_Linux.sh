#!/bin/bash
cd backend
echo "Starting WiFi Security Monitor Server..."
if [ -f "venv/bin/python" ]; then
    venv/bin/python main.py
else
    echo "Virtual environment not found! Using system python..."
    pip3 install -r requirements.txt
    python3 main.py
fi
