@echo off
setlocal enabledelayedexpansion
title AI-IDS Dashboard

echo.
echo  ================================================================
echo   AI MULTI-LAYER INTRUSION DETECTION SYSTEM FOR IOT NETWORKS
echo   Spring Boot 3.3  ^|  Java 22  ^|  CIC-IoT 2023  ^|  XGBoost
echo  ================================================================
echo.

:: ── Step 1: Find Java ────────────────────────────────────────────────────────
set JAVA_HOME=C:\Program Files\Java\jdk-22
set JAVA_EXE=%JAVA_HOME%\bin\java.exe

if not exist "%JAVA_EXE%" (
    echo [WARN] Java not found at: %JAVA_HOME%
    echo [INFO] Trying to auto-detect Java...
    for /f "tokens=*" %%i in ('where java 2^>nul') do set JAVA_FOUND=%%i
    if "!JAVA_FOUND!"=="" (
        echo.
        echo [ERROR] Java 22 not found. Please install from:
        echo         https://www.oracle.com/java/technologies/downloads/
        echo.
        pause
        exit /b 1
    )
    echo [INFO] Found Java at: !JAVA_FOUND!
) else (
    echo [1/3] Java detected at: %JAVA_HOME%
)

:: ── Step 2: Find Maven ───────────────────────────────────────────────────────
set "PROJECT_DIR=C:\AI_IDS_IOT_PROJECT_MAIN_FOLDER"
set "MVN=%PROJECT_DIR%\.mvn_cache\apache-maven-3.9.16\bin\mvn.cmd"
set "POM=%PROJECT_DIR%\pom.xml"

if not exist "%MVN%" (
    echo.
    echo [ERROR] Maven not found at: %MVN%
    echo [INFO]  Expected path: %PROJECT_DIR%\.mvn_cache\apache-maven-3.9.16\
    echo.
    echo [FIX]   Run this command to download Maven manually:
    echo         powershell -Command "Invoke-WebRequest -Uri 'https://archive.apache.org/dist/maven/maven-3/3.9.16/binaries/apache-maven-3.9.16-bin.zip' -OutFile '%TEMP%\maven.zip'"
    echo.
    pause
    exit /b 1
)

if not exist "%POM%" (
    echo.
    echo [ERROR] pom.xml not found at: %POM%
    echo [INFO]  Make sure you are running this from the correct folder.
    echo.
    pause
    exit /b 1
)

echo [2/3] Maven detected: %MVN%
echo [3/3] Project found:  %POM%
echo.
echo [OK] All checks passed. Building and starting server...
echo [INFO] First run may take 2-3 minutes to download Spring Boot libs.
echo.
echo  Dashboard URL : http://localhost:8080
echo  API Health    : http://localhost:8080/api/health
echo  Press Ctrl+C to stop the server.
echo  ================================================================
echo.

:: ── Step 3: Kill any existing process on port 8080 ──────────────────────────
echo [INFO] Freeing port 8080 if in use...
for /f "tokens=5" %%P in ('netstat -aon 2^>nul ^| findstr LISTENING ^| findstr ":8080"') do taskkill /PID %%P /F >nul 2>&1
timeout /t 1 /nobreak >nul

:: ── Step 4: Run ──────────────────────────────────────────────────────────────
"%MVN%" -f "%POM%" clean spring-boot:run "-Dspring-boot.run.jvmArguments=--add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED"

set EXIT_CODE=%ERRORLEVEL%

echo.
if %EXIT_CODE% NEQ 0 (
    echo [ERROR] Server exited with error code: %EXIT_CODE%
    echo [INFO]  Common causes:
    echo         - Port 8080 already in use: run  netstat -ano ^| findstr :8080
    echo         - Java version mismatch: check  java -version
    echo         - Missing dependency: check internet connection and try again
) else (
    echo [INFO] Server stopped normally.
)

echo.
pause
