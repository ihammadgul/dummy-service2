"""Authentication for Service2 (Resource Service/Microservice)

This service ONLY verifies tokens. It never issues them.
All token issuance is handled by Service1 (Auth Service).
"""
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from jwt.exceptions import InvalidTokenError
from typing import Optional

from app.core.config import settings
from app.core.jwks_client import jwks_client


# Use HTTPBearer for token extraction (microservices don't need OAuth2PasswordBearer)
security = HTTPBearer()


class TokenPayload:
    """Represents decoded and validated JWT payload"""
    
    def __init__(self, payload: dict):
        self.sub: str = payload.get("sub")  # User ID
        self.email: str = payload.get("email")
        self.role: str = payload.get("role")
        self.exp: int = payload.get("exp")
        self.iat: int = payload.get("iat")
        self.iss: str = payload.get("iss")
        self.aud: str = payload.get("aud")
        self.jti: str = payload.get("jti")  # Token ID


async def verify_token(token: str) -> TokenPayload:
    """
    Verify JWT token using public key from JWKS endpoint
    
    This function:
    1. Extracts the 'kid' from token header
    2. Fetches the corresponding public key from JWKS
    3. Verifies signature, expiration, issuer, and audience
    4. Returns decoded payload
    
    Args:
        token: JWT token string
        
    Returns:
        TokenPayload: Decoded and validated token payload
        
    Raises:
        HTTPException: If token is invalid
    """
    try:
        # Decode header to get kid (key ID)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        
        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing 'kid' in header",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get public key from JWKS
        try:
            public_key_pem = await jwks_client.get_signing_key(kid)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Failed to fetch public key: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Verify and decode token
        payload = jwt.decode(
            token,
            public_key_pem,
            algorithms=[settings.ALGORITHM],
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            }
        )
        
        return TokenPayload(payload)
        
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> TokenPayload:
    """
    Dependency to get current authenticated user from JWT token
    
    Extracts and verifies the JWT token from the Authorization header.
    This is the main dependency for protecting endpoints.
    
    Usage:
        @router.get("/protected")
        async def protected_route(user: TokenPayload = Depends(get_current_user)):
            return {"user_id": user.sub, "email": user.email}
    """
    token = credentials.credentials
    return await verify_token(token)


def require_role(required_role: str):
    """
    Dependency factory to enforce role-based access control
    
    Usage:
        @router.get("/admin", dependencies=[Depends(require_role("admin"))])
        async def admin_route():
            return {"message": "Admin access granted"}
    """
    async def role_checker(user: TokenPayload = Depends(get_current_user)):
        if user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role}"
            )
        return user
    
    return role_checker


async def get_optional_user(
    request: Request
) -> Optional[TokenPayload]:
    """
    Optional authentication dependency
    
    Returns user if valid token is provided, None otherwise.
    Does not raise an exception if token is missing or invalid.
    
    Usage:
        @router.get("/public-or-private")
        async def route(user: Optional[TokenPayload] = Depends(get_optional_user)):
            if user:
                return {"message": f"Hello {user.email}"}
            return {"message": "Hello guest"}
    """
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    
    token = auth_header.replace("Bearer ", "")
    
    try:
        return await verify_token(token)
    except HTTPException:
        return None
