"""Security utilities for Service2 (Resource Service)

IMPORTANT: This service does NOT issue tokens.
Token issuance is exclusively handled by Service1 (Auth Service).

This module is kept for potential future utility functions.
For token verification, see app.core.auth module.
"""

# Service2 should NEVER issue tokens
# All authentication is handled by verifying tokens from Service1

# If you need password hashing utilities, they can be added here
# But token creation functions should NOT exist in this service

from passlib.context import CryptContext

# Password context (only if this service manages its own user data)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash (if needed for local user management)"""
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    """Hash a password (if needed for local user management)"""
    return pwd_context.hash(password)