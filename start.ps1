# Quick Start Script for Windows (PowerShell)

Write-Host "🔒 Vulnerability Detection System - Quick Start" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Check if Docker is installed
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Docker is not installed. Please install Docker Desktop first." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Docker Compose is not installed. Please install Docker Compose first." -ForegroundColor Red
    exit 1
}

# Check if .env file exists
if (-not (Test-Path .env)) {
    Write-Host "⚠️  No .env file found. Creating from .env.example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
    Write-Host "✅ Created .env file. Please edit it with your API keys." -ForegroundColor Green
    Write-Host "   - NVD_API_KEY: Get from https://nvd.nist.gov/developers/request-an-api-key"
    Write-Host "   - GITHUB_TOKEN: Get from https://github.com/settings/tokens"
    Read-Host "Press Enter after updating .env file"
}

# Create necessary directories
Write-Host "📁 Creating directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path data, models, logs, reports | Out-Null

# Start Docker containers
Write-Host "🐳 Starting Docker containers..." -ForegroundColor Cyan
docker-compose up -d

# Wait for MongoDB to be ready
Write-Host "⏳ Waiting for MongoDB to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check if containers are running
$mongoRunning = docker ps | Select-String "vuln_detection_mongodb"
if ($mongoRunning) {
    Write-Host "✅ MongoDB is running" -ForegroundColor Green
} else {
    Write-Host "❌ MongoDB failed to start" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "🎉 Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Access MongoDB Express UI at: http://localhost:8081" -ForegroundColor Cyan
Write-Host "   Username: admin"
Write-Host "   Password: admin123"
Write-Host ""
Write-Host "🚀 Next steps:" -ForegroundColor Cyan
Write-Host "   1. Run data collection:  docker-compose exec ml_app python src/main.py --phase sample"
Write-Host "   2. Explore data:         docker-compose exec ml_app python src/main.py --phase explore"
Write-Host "   3. Preprocess data:      docker-compose exec ml_app python src/main.py --phase modify"
Write-Host "   4. Train models:         docker-compose exec ml_app python src/main.py --phase model"
Write-Host "   5. Evaluate models:      docker-compose exec ml_app python src/main.py --phase assess"
Write-Host ""
Write-Host "   Or run complete pipeline: docker-compose exec ml_app python src/main.py --phase all"
Write-Host ""
Write-Host "📝 View logs: docker-compose logs -f ml_app" -ForegroundColor Yellow
Write-Host "🛑 Stop containers: docker-compose down" -ForegroundColor Yellow
