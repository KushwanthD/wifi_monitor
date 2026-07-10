@echo off
cd backend
echo Starting WiFi Security Monitor Server...
if exist venv\Scripts\python.exe (
    venv\Scripts\python.exe main.py
) else (
    echo Virtual environment not found! Using system python...
    pip install -r requirements.txt
    python main.py
)
pause
