Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "venv\Scripts\pythonw.exe -m uvicorn main:app --host 0.0.0.0 --port 8000", 0
Set WshShell = Nothing
