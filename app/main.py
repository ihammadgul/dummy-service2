"""
Service2 - Resource Service (Microservice)

This is a resource/microservice that:
- Verifies JWT tokens using public keys from JWKS
- Never issues tokens (only Auth Service does that)
- Enforces authorization based on token claims
- Operates independently without calling Auth Service for each request
"""
from fastapi import FastAPI, Depends
from app.core.config import settings

from contextlib import asynccontextmanager
from app.database.engine import init_db, close_db

from fastapi.middleware.cors import CORSMiddleware

from app.utilities.middleware import get_current_user, require_role, TokenPayload


@asynccontextmanager
async def lifespan(app: FastAPI):
     """Lifecycle manager for startup and shutdown"""
     # Startup logic
     await init_db()
     print("=" * 60)
     print(f"🚀 {settings.PROJECT_NAME} - Microservice Started")
     print("=" * 60)
     print("Database Connection Initialized")
     print(f"JWKS URL: {settings.JWKS_URL}")
     print(f"Expected Issuer: {settings.JWT_ISSUER}")
     print(f"Expected Audience: {settings.JWT_AUDIENCE}")
     print("Token Verification: RS256 with JWKS")
     print("=" * 60)
     yield
     # Shutdown logic
     await close_db()
     print("Database Connection Disposed")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Resource Service with Token Verification",
    version="1.0.0",
    lifespan=lifespan
)

# Include CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update with specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "service": settings.PROJECT_NAME,
        "status": "running",
        "type": "resource_service",
        "auth_method": "JWT verification via JWKS"
    }


@app.get("/protected")
async def protected_route(user: TokenPayload = Depends(get_current_user)):
    """Example protected endpoint - requires valid JWT"""
    return {
        "message": "This is a protected route",
        "user_id": user.sub,
        "email": user.email,
        "role": user.role
    }


@app.get("/admin-only", dependencies=[Depends(require_role("admin"))])
async def admin_only_route():
    """Example admin-only endpoint - requires admin role"""
    return {
        "message": "This is an admin-only route",
        "access": "granted"
    }

