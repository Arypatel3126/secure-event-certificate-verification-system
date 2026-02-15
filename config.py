"""Application configuration."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///certificates.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CERTIFICATES_FOLDER = BASE_DIR / 'certificates'

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
