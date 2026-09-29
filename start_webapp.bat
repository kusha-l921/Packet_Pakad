@echo off
setlocal EnableDelayedExpansion

title IPsec Sentinel - Autonomous Cybersecurity Workstation Launcher
echo ======================================================================
echo                IPSEC SENTINEL - WORKSTATION LAUNCHER
echo        AI-Powered IPsec Protocol Analyzer & Security Framework
echo ======================================================================

cd /d C:\ipsec-testbed

echo.
echo [1/3] Starting IPsec Sentinel Python Backend API (Port 8000)...
start "IPsec Sentinel Backend API (Port 8000)" cmd /k "python -m uvicorn backend.server:app --host 0.0.0.0 --port 8000 --reload"

echo [2/3] Starting Next.js Security Dashboard (Port 3001)...
cd /d C:\ipsec-testbed\frontend
start "IPsec Sentinel WebApp (Port 3001)" cmd /k "npm run dev"

echo [3/3] Waiting for services to initialize...
timeout /t 4 /nobreak >nul

echo.
echo ======================================================================
echo  Sentinel Workstation Successfully Launched!
echo  - Frontend Dashboard: http://localhost:3001
echo  - Backend API:        http://localhost:8000/docs
echo.
echo  From the WebApp (/testbed or Dashboard), you can directly trigger
echo  testbed deployment, strongSwan configuration, sniffer attachment,
echo  and real traffic assessment.
echo ======================================================================
echo.

start http://localhost:3001

pause
