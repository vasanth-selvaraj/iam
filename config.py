import os

# Database URL (use PostgreSQL in prod, SQLite for dev)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./idp.db")

# OAuth2 settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Fixed client apps
FIXED_APPS = {
    "mdx": {"name": "MDX App", "redirect_uris": ["http://localhost:8001/auth/callback"]},
    "gdx": {"name": "GDX App", "redirect_uris": ["http://localhost:8002/auth/callback"]}
}