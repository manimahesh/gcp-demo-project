#!/bin/bash

# OWASP Top 10 Demo - Docker Run Script
# This script builds and runs the OWASP demo application in Docker

set -e

CONTAINER_NAME="owasp-demo"
IMAGE_NAME="owasp-top10-demo"
PORT="${PORT:-8080}"

echo "=========================================="
echo "OWASP Top 10 Demo - Docker Launcher"
echo "=========================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed or not in PATH"
    echo "Please install Docker from https://www.docker.com/get-started"
    exit 1
fi

echo "✓ Docker found"

# Stop and remove existing container if running
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "🧹 Removing existing container..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
fi

# Build the image
echo ""
echo "🔨 Building Docker image..."
docker build -t $IMAGE_NAME .

if [ $? -eq 0 ]; then
    echo "✓ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# Run the container
echo ""
echo "🚀 Starting container..."
docker run -d \
    -p $PORT:80 \
    --name $CONTAINER_NAME \
    --restart unless-stopped \
    $IMAGE_NAME

if [ $? -eq 0 ]; then
    echo "✓ Container started successfully"
else
    echo "❌ Failed to start container"
    exit 1
fi

# Wait a moment for container to start
sleep 2

# Check if container is running
if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo ""
    echo "=========================================="
    echo "✅ OWASP Top 10 Demo is now running!"
    echo "=========================================="
    echo ""
    echo "🌐 Access the application at:"
    echo "   http://localhost:$PORT"
    echo ""
    echo "📋 Useful commands:"
    echo "   View logs:    docker logs $CONTAINER_NAME"
    echo "   Stop:         docker stop $CONTAINER_NAME"
    echo "   Start:        docker start $CONTAINER_NAME"
    echo "   Remove:       docker rm -f $CONTAINER_NAME"
    echo ""
    echo "Press Ctrl+C to stop monitoring logs (container will keep running)"
    echo "=========================================="
    echo ""

    # Follow logs
    docker logs -f $CONTAINER_NAME
else
    echo "❌ Container failed to start"
    echo "Check logs with: docker logs $CONTAINER_NAME"
    exit 1
fi
