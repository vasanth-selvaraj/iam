from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="user")  # "super_admin", "admin", "user"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class OAuth2Client(Base):
    __tablename__ = "oauth2_clients"
    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String, unique=True, index=True)
    client_secret = Column(String)
    app_name = Column(String)  # "mdx" or "gdx"
    redirect_uris = Column(Text)  # JSON string
    is_active = Column(Boolean, default=True)

class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True)
    client_id = Column(String, ForeignKey("oauth2_clients.client_id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    redirect_uri = Column(String)
    expires_at = Column(DateTime)

class AccessToken(Base):
    __tablename__ = "access_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    client_id = Column(String, ForeignKey("oauth2_clients.client_id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime)