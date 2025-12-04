#!/bin/bash

# Quick Start Script for Vulnerability Detection System

echo "🔒 Vulnerability Detection System - Quick Start"
echo "================================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating from .env.example..."
    cp .env.example .env
    echo "✅ Created .env file. Please edit it with your API keys."
    echo "   - NVD_API_KEY: Get from https://nvd.nist.gov/developers/request-an-api-key"
    echo "   - GITHUB_TOKEN: Get from https://github.com/settings/tokens"
    read -p "Press Enter after updating .env file..."
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p data models logs reports

# Start Docker containers
echo "🐳 Starting Docker containers..."
docker-compose up -d

# Wait for MongoDB to be ready
echo "⏳ Waiting for MongoDB to be ready..."
sleep 10

# Check if containers are running
if docker ps | grep -q vuln_detection_mongodb; then
    echo "✅ MongoDB is running"
else
    echo "❌ MongoDB failed to start"
    exit 1
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📊 Access MongoDB Express UI at: http://localhost:8081"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "🚀 Next steps:"
echo "   1. Run data collection:  docker-compose exec ml_app python src/main.py --phase sample"
echo "   2. Explore data:         docker-compose exec ml_app python src/main.py --phase explore"
echo "   3. Preprocess data:      docker-compose exec ml_app python src/main.py --phase modify"
echo "   4. Train models:         docker-compose exec ml_app python src/main.py --phase model"
echo "   5. Evaluate models:      docker-compose exec ml_app python src/main.py --phase assess"
echo ""
echo "   Or run complete pipeline: docker-compose exec ml_app python src/main.py --phase all"
echo ""
echo "📝 View logs: docker-compose logs -f ml_app"
echo "🛑 Stop containers: docker-compose down"
