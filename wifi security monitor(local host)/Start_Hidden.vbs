Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd /c cd backend && if exist venv\Scripts\pythonw.exe (venv\Scripts\pythonw.exe main.py) else (pythonw main.py)", 0, False
