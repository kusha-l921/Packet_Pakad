@echo off
setlocal EnableDelayedExpansion

title IPsec Testbed Orchestrator
echo ======================================================================
echo           IPsec Testbed ^& Analyzer Automated Launcher
echo ======================================================================

cd /d C:\ipsec-testbed

echo [1/5] Starting Docker containers...
docker compose up -d
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to bring up Docker containers.
    pause
    exit /b %ERRORLEVEL%
)

echo [2/5] Waiting for strongSwan daemons to become ready...
set /a attempts=0
:wait_hq
docker exec gw-hq swanctl --stats >nul 2>&1
if %ERRORLEVEL% equ 0 goto hq_ready
set /a attempts+=1
if !attempts! geq 30 (
    echo [ERROR] Timed out waiting for gw-hq charon daemon to become ready.
    docker compose logs gw-hq
    pause
    exit /b 1
)
timeout /t 1 /nobreak >nul
goto wait_hq

:hq_ready
echo  [+] gw-hq strongSwan charon daemon is ready.

set /a attempts=0
:wait_branch
docker exec gw-branch swanctl --stats >nul 2>&1
if %ERRORLEVEL% equ 0 goto branch_ready
set /a attempts+=1
if !attempts! geq 30 (
    echo [ERROR] Timed out waiting for gw-branch charon daemon to become ready.
    docker compose logs gw-branch
    pause
    exit /b 1
)
timeout /t 1 /nobreak >nul
goto wait_branch

:branch_ready
echo  [+] gw-branch strongSwan charon daemon is ready.

echo [3/5] Loading configuration and certificates into strongSwan gateways...
echo  - Loading gw-hq...
docker exec gw-hq swanctl --load-all
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to load configuration on gw-hq.
    pause
    exit /b %ERRORLEVEL%
)

echo  - Loading gw-branch...
docker exec gw-branch swanctl --load-all
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to load configuration on gw-branch.
    pause
    exit /b %ERRORLEVEL%
)
echo  [+] Configurations and certificates successfully loaded on both gateways.

echo [4/5] Spawning Sniffer ^& Analytics Engine in a dedicated window...
set /a attempts=0
:wait_analyzer
docker inspect -f "{{.State.Running}}" ipsec-analyzer 2>nul | findstr "true" >nul 2>&1
if %ERRORLEVEL% equ 0 goto analyzer_running
set /a attempts+=1
if !attempts! geq 30 (
    echo [ERROR] Timed out waiting for ipsec-analyzer container to start.
    docker compose logs analyzer
    pause
    exit /b 1
)
timeout /t 1 /nobreak >nul
goto wait_analyzer

:analyzer_running
echo  [+] ipsec-analyzer container is running.
start "IPsec Real-Time Sniffer (Container)" cmd /k "docker exec -it ipsec-analyzer python sniffer.py -i eth0 -p -o output"

echo Waiting for sniffer/analytics engine to attach to eth0...
set /a attempts=0
:wait_sniffer
docker exec ipsec-analyzer pgrep -f "python.*sniffer\.py" >nul 2>&1
if %ERRORLEVEL% equ 0 goto sniffer_ready
set /a attempts+=1
if !attempts! geq 10 (
    echo  [NOTE] Sniffer launch command initiated; proceeding to testbed generator.
    goto sniffer_ready
)
timeout /t 1 /nobreak >nul
goto wait_sniffer

:sniffer_ready
echo  [+] Analyzer / sniffer is ready.

echo [5/5] Launching Testbed Console...
echo ======================================================================
start "Testbed Generator" cmd /k "python testbed_generator.py"

if %ERRORLEVEL% neq 0 (
    echo [ERROR] testbed_generator.py exited with error code %ERRORLEVEL%.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ======================================================================
echo Traffic generation routine completed.
echo Optional next action: run daemon_credential_exporter.py to ingest certs.
echo ======================================================================
pause
