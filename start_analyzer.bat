@echo off
echo ========================================
echo   AI TRAFFIC ANALYZER - QUICK START
echo ========================================
echo.
echo Step 1: Starting ML Model API...
echo.
start "ML Model API" cmd /k "python app.py"
timeout /t 5 /nobreak > nul
echo.
echo Step 2: Starting Traffic Analyzer...
echo.
start "Traffic Analyzer" cmd /k "python traffic_analyzer.py"
echo.
echo ========================================
echo   BOTH SERVICES STARTED!
echo ========================================
echo.
echo Now configure your browser:
echo   1. Settings ^> Network ^> Proxy
echo   2. Address: 127.0.0.1
echo   3. Port: 8080
echo   4. Save and start browsing!
echo.
echo Watch the Traffic Analyzer window for
echo real-time analysis of every request!
echo.
pause
