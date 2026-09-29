@echo off
setlocal EnableDelayedExpansion

echo ======================================================================
echo           IPsec Testbed ^& Analyzer Startup Orchestrator
echo ======================================================================


cd /d C:\ipsec-testbed

echo [1/5] Bringing up Docker Compose environment...
docker compose up -d
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker compose failed to start containers.
    pause
    exit /b %ERRORLEVEL%
)

echo [2/5] Waiting for strongSwan daemons to initialize...
set /a attempts=0
:wait_hq
docker exec gw-hq swanctl --stats >nul 2>&1
if %ERRORLEVEL% equ 0 goto hq_ok
set /a attempts+=1
if !attempts! geq 30 (
    echo [ERROR] gw-hq charon daemon failed to initialize.
    pause
    exit /b 1
)
timeout /t 1 /nobreak >nul
goto wait_hq

:hq_ok
set /a attempts=0
:wait_branch
docker exec gw-branch swanctl --stats >nul 2>&1
if %ERRORLEVEL% equ 0 goto branch_ok
set /a attempts+=1
if !attempts! geq 30 (
    echo [ERROR] gw-branch charon daemon failed to initialize.
    pause
    exit /b 1
)
timeout /t 1 /nobreak >nul
goto wait_branch

:branch_ok
echo  [+] Daemons initialized successfully.

echo [3/5] Loading configuration and certificates into strongSwan daemons...
echo  - Loading gw-hq...
docker exec gw-hq swanctl --load-all
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to load configuration on gw-hq.
    pause
    exit /b 1
)
echo  - Loading gw-branch...
docker exec gw-branch swanctl --load-all
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to load configuration on gw-branch.
    pause
    exit /b 1
)


echo [4/5] Establishing IPsec Tunnel (Child SA: corp-traffic-sa)...
docker exec gw-hq swanctl --initiate --child corp-traffic-sa
if %ERRORLEVEL% neq 0 (
    echo [WARN] Initiation command exited with non-zero status. Checking active SAs...
)

echo [5/5] Verifying Active Security Associations...
docker exec gw-hq swanctl --list-sas

echo.
echo ======================================================================
echo  Setup Complete! 
echo  Next actions:
echo   1. Start Sniffer: docker exec -it ipsec-analyzer python sniffer.py -i eth0 -p -o output
echo   2. Send Traffic:  docker exec -it gw-hq ping -c 10 172.28.0.3
echo   3. Run Exporter:  python daemon_credential_exporter.py
echo ======================================================================

pause