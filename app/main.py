"""
Main entry point for IPDR system
"""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import time
from dotenv import load_dotenv

from app.database import engine, Base
from app.routers import ipdr, security, collector, cgnat
from app.utils.logger import logger

load_dotenv()

# Create database tables
Base.metadata.create_all(bind=engine)

logger.info("IPDR System starting up...")

app = FastAPI(
    title="IPDR System - Traffic Detail Management and Analysis",
    description="Comprehensive system for collecting, storing, and analyzing network traffic data",
    version="1.0.0"
)

# Configure CORS from CORS_ORIGINS (comma-separated). Default: * without credentials.
cors_origins_raw = os.getenv("CORS_ORIGINS", "*").strip()
if cors_origins_raw == "*":
    cors_origins = ["*"]
    cors_credentials = False
else:
    cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
    cors_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(ipdr.router)
app.include_router(security.router)
app.include_router(collector.router)
app.include_router(cgnat.router)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests"""
    start_time = time.time()
    
    # Log request
    logger.info(f"{request.method} {request.url.path} - Client: {request.client.host if request.client else 'Unknown'}")
    
    # Process request
    response = await call_next(request)
    
    # Calculate duration
    duration = time.time() - start_time
    
    # Log response
    logger.info(f"{request.method} {request.url.path} - Status: {response.status_code} - Duration: {duration:.3f}s")
    
    return response

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Traffic management dashboard page"""
    dashboard_path = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")
    if os.path.exists(dashboard_path):
        with open(dashboard_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard not found</h1>"


@app.get("/", response_class=HTMLResponse)
async def root():
    """Home page"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IPDR System - Traffic Detail Management and Analysis</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .container {
                background: white;
                border-radius: 20px;
                padding: 40px;
                max-width: 800px;
                width: 100%;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 2.5em;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
                font-size: 1.2em;
            }
            .features {
                list-style: none;
                margin: 30px 0;
            }
            .features li {
                padding: 15px;
                margin: 10px 0;
                background: #f8f9fa;
                border-radius: 10px;
                border-left: 4px solid #667eea;
            }
            .features li strong {
                color: #667eea;
            }
            .links {
                margin-top: 30px;
                display: flex;
                gap: 15px;
                flex-wrap: wrap;
            }
            .btn {
                display: inline-block;
                padding: 12px 30px;
                background: #667eea;
                color: white;
                text-decoration: none;
                border-radius: 8px;
                transition: all 0.3s;
            }
            .btn:hover {
                background: #764ba2;
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }
            .btn-secondary {
                background: #6c757d;
            }
            .btn-secondary:hover {
                background: #5a6268;
            }
            .status-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
            }
            .status-active {
                background-color: #28a745;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>IPDR System</h1>
            <p class="subtitle">Traffic Detail Management and Analysis</p>
            
            <p style="margin-bottom: 20px; line-height: 1.8; color: #555;">
                IPDR (Internet Protocol Detail Record) system is a comprehensive solution for collecting, 
                storing, and analyzing network traffic data, providing detailed monitoring of connections, 
                security threat detection, and resource optimization.
            </p>
            
            <ul class="features">
                <li><strong style="color: #28a745;">Traffic Data Collection:</strong> Complete recording of IP connection details</li>
                <li><strong style="color: #17a2b8;">Deep Packet Inspection (DPI):</strong> Automatic identification of service types and protocols</li>
                <li><strong style="color: #ffc107;">Advanced Reporting:</strong> Generate analytical reports from traffic data</li>
                <li><strong style="color: #dc3545;">Threat Detection:</strong> Identify suspicious activities and attacks</li>
                <li><strong style="color: #6f42c1;">Billing Support:</strong> Prepaid, Postpaid, and Hybrid models</li>
            </ul>
            
            <div class="links">
                <a href="/dashboard" class="btn">Dashboard</a>
                <a href="/docs" class="btn">API Documentation</a>
                <a href="/redoc" class="btn btn-secondary">ReDoc</a>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/health")
async def health_check():
    """System health check"""
    logger.info("Health check requested")
    return {
        "status": "healthy",
        "message": "IPDR system is running"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
