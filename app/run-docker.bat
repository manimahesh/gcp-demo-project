@echo off
REM OWASP Top 10 Demo - Docker Run Script (Windows)
REM This script builds and runs the OWASP demo application in Docker

setlocal enabledelayedexpansion

set CONTAINER_NAME=owasp-demo
set IMAGE_NAME=owasp-top10-demo
if "%PORT%"=="" set PORT=8080

echo ==========================================
echo OWASP Top 10 Demo - Docker Launcher
echo ==========================================
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Error: Docker is not installed or not in PATH
    echo Please install Docker from https://www.docker.com/get-started
    pause
    exit /b 1
)

echo ✓ Docker found

REM Stop and remove existing container if running
docker ps -a --format "{{.Names}}" | findstr /X "%CONTAINER_NAME%" >nul 2>&1
if not errorlevel 1 (
    echo 🧹 Removing existing container...
    docker stop %CONTAINER_NAME% >nul 2>&1
    docker rm %CONTAINER_NAME% >nul 2>&1
)

REM Build the image
echo.
echo 🔨 Building Docker image...
docker build -t %IMAGE_NAME% .

if errorlevel 1 (
    echo ❌ Build failed
    pause
    exit /b 1
)

echo ✓ Build successful

REM Run the container
echo.
echo 🚀 Starting container...
docker run -d -p %PORT%:80 --name %CONTAINER_NAME% --restart unless-stopped %IMAGE_NAME%

if errorlevel 1 (
    echo ❌ Failed to start container
    pause
    exit /b 1
)

echo ✓ Container started successfully

REM Wait a moment for container to start
timeout /t 2 /nobreak >nul

REM Check if container is running
docker ps --format "{{.Names}}" | findstr /X "%CONTAINER_NAME%" >nul 2>&1
if errorlevel 1 (
    echo ❌ Container failed to start
    echo Check logs with: docker logs %CONTAINER_NAME%
    pause
    exit /b 1
)

echo.
echo ==========================================
echo ✅ OWASP Top 10 Demo is now running!
echo ==========================================
echo.
echo 🌐 Access the application at:
echo    http://localhost:%PORT%
echo.
echo 📋 Useful commands:
echo    View logs:    docker logs %CONTAINER_NAME%
echo    Stop:         docker stop %CONTAINER_NAME%
echo    Start:        docker start %CONTAINER_NAME%
echo    Remove:       docker rm -f %CONTAINER_NAME%
echo.
echo Press Ctrl+C to stop monitoring logs (container will keep running)
echo ==========================================
echo.

REM Follow logs
docker logs -f %CONTAINER_NAME%
