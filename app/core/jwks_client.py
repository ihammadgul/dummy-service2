"""JWKS fetching & caching - JWKS Client for Service2 (Microservice)

Fetches and caches public keys from Auth Service (Service1) JWKS endpoint
"""
import httpx
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict
from app.core.config import settings


class JWKSClient:
    """Client to fetch and cache JWKS from Auth Service"""
    
    def __init__(self):
        self.jwks_cache: Optional[Dict] = None
        self.cache_expires_at: Optional[datetime] = None
        self.cache_ttl_minutes = 30  # Cache for 30 minutes
    
    async def get_jwks(self) -> Dict:
        """
        Get JWKS from cache or fetch from Auth Service
        
        Returns:
            dict: JWKS response with public keys
        """
        now = datetime.now(timezone.utc)
        
        # Return cached JWKS if still valid
        if self.jwks_cache and self.cache_expires_at and now < self.cache_expires_at:
            return self.jwks_cache
        
        # Fetch fresh JWKS
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(settings.JWKS_URL)
                response.raise_for_status()
                
                self.jwks_cache = response.json()
                self.cache_expires_at = now + timedelta(minutes=self.cache_ttl_minutes)
                
                return self.jwks_cache
                
        except httpx.HTTPError as e:
            # If cache exists but fetch failed, use stale cache
            if self.jwks_cache:
                return self.jwks_cache
            raise Exception(f"Failed to fetch JWKS: {str(e)}")
    
    async def get_signing_key(self, kid: str) -> str:
        """
        Get the public key (PEM format) for a given key ID
        
        Args:
            kid: Key ID from JWT header
            
        Returns:
            str: Public key in PEM format
        """
        jwks = await self.get_jwks()
        
        # Find the key with matching kid
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                # Convert JWK to PEM
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                
                # Get n and e from JWK
                import base64
                
                def base64url_decode(val: str) -> int:
                    """Decode base64url to integer"""
                    # Add padding if needed
                    padding = 4 - (len(val) % 4)
                    if padding != 4:
                        val += '=' * padding
                    
                    decoded = base64.urlsafe_b64decode(val)
                    return int.from_bytes(decoded, byteorder='big')
                
                n = base64url_decode(key["n"])
                e = base64url_decode(key["e"])
                
                # Create RSA public key
                public_numbers = rsa.RSAPublicNumbers(e, n)
                public_key = public_numbers.public_key()
                
                # Convert to PEM
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                return pem.decode('utf-8')
        
        raise ValueError(f"No key found with kid: {kid}")


# Global JWKS client instance
jwks_client = JWKSClient()
