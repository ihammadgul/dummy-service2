from pydantic_settings import BaseSettings


class Settings(BaseSettings):
     PROJECT_NAME: str = "Resource Service"
     DATABASE_URL: str
     
     # JWKS endpoint from Auth Service (Service1)
     JWKS_URL: str = "http://localhost:8001/auth/.well-known/jwks.json"
     
     # JWT validation settings
     ALGORITHM: str = "RS256"
     JWT_ISSUER: str = "auth.name"
     JWT_AUDIENCE: str = "name.services"
     
     class Config:
          env_file = ".env"

settings = Settings()