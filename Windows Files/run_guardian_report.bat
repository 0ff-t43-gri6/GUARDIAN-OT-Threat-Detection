@echo off
echo =======================================
echo   GUARDIAN — Auto Report Generator
echo =======================================

cd C:\Users\shiv0\Desktop\OT_project

C:\Users\shiv0\Desktop\OT_project\opcua-server\.venv\Scripts\python.exe guardian_report_generator.py

echo Report generated: %date% %time%
echo Saved to: GUARDIAN_Security_Report.pdf