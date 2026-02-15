"""Database models for the Secure Event Certificate Verification System."""
import hashlib
import uuid
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Admin(UserMixin, db.Model):
    """Admin user for certificate management."""
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        """Hash and store password using werkzeug.security."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password against stored hash."""
        return check_password_hash(self.password_hash, password)


class Certificate(db.Model):
    """Certificate record with unique verification hash."""
    __tablename__ = 'certificates'
    id = db.Column(db.Integer, primary_key=True)
    certificate_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    participant_name = db.Column(db.String(200), nullable=False)
    university_id = db.Column(db.String(100), nullable=False)
    event_name = db.Column(db.String(300), nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    hash_value = db.Column(db.String(64), nullable=False)

    @staticmethod
    def generate_hash(certificate_id, participant_name, university_id, event_name, date_str):
        """Generate SHA-256 hash for verification."""
        data = f"{certificate_id}|{participant_name}|{university_id}|{event_name}|{date_str}"
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def create_certificate(participant_name, university_id, event_name, certificate_id=None):
        """Create a new certificate with unique ID and hash."""
        if certificate_id is None:
            certificate_id = str(uuid.uuid4())
        issue_date = datetime.utcnow()
        date_str = issue_date.strftime('%Y-%m-%d %H:%M:%S')
        hash_value = Certificate.generate_hash(
            certificate_id, participant_name, university_id, event_name, date_str
        )
        return Certificate(
            certificate_id=certificate_id,
            participant_name=participant_name,
            university_id=university_id,
            event_name=event_name,
            hash_value=hash_value
        )
