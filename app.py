"""Secure Digital Certificate Verification System - Flask application."""
import io
import uuid as uuid_module
from pathlib import Path

import qrcode
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from config import Config
from models import db, Admin, Certificate

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'
login_manager.session_protection = 'strong'


@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login."""
    return Admin.query.get(int(user_id))


def init_db():
    """Initialize database and create default admin if needed."""
    Path(app.config['CERTIFICATES_FOLDER']).mkdir(exist_ok=True)
    with app.app_context():
        db.create_all()
        if not Admin.query.filter_by(username='admin').first():
            admin = Admin(username='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()


def generate_qr_code(data: str) -> bytes:
    """Generate QR code image as bytes."""
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()


def create_pdf(cert: Certificate, verification_url: str) -> bytes:
    """Create certificate PDF with ReportLab."""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Title
    c.setFont('Helvetica-Bold', 24)
    c.drawCentredString(width / 2, height - 1.2 * inch, 'Certificate of Participation')

    # Decorative line
    c.setLineWidth(2)
    c.line(width / 4, height - 1.5 * inch, 3 * width / 4, height - 1.5 * inch)

    # Certificate details
    c.setFont('Helvetica', 12)
    y = height - 2 * inch
    line_height = 0.4 * inch

    c.setFont('Helvetica-Bold', 11)
    c.drawString(1 * inch, y, 'Certificate ID:')
    c.setFont('Helvetica', 11)
    c.drawString(2.5 * inch, y, cert.certificate_id)
    y -= line_height

    c.setFont('Helvetica-Bold', 11)
    c.drawString(1 * inch, y, 'Participant Name:')
    c.setFont('Helvetica', 11)
    c.drawString(2.5 * inch, y, cert.participant_name)
    y -= line_height

    c.setFont('Helvetica-Bold', 11)
    c.drawString(1 * inch, y, 'University ID:')
    c.setFont('Helvetica', 11)
    c.drawString(2.5 * inch, y, cert.university_id)
    y -= line_height

    c.setFont('Helvetica-Bold', 11)
    c.drawString(1 * inch, y, 'Event Name:')
    c.setFont('Helvetica', 11)
    c.drawString(2.5 * inch, y, cert.event_name)
    y -= line_height

    c.setFont('Helvetica-Bold', 11)
    c.drawString(1 * inch, y, 'Issue Date:')
    c.setFont('Helvetica', 11)
    date_str = cert.issue_date.strftime('%B %d, %Y')
    c.drawString(2.5 * inch, y, date_str)

    # QR Code
    qr_bytes = generate_qr_code(verification_url)
    qr_img = ImageReader(io.BytesIO(qr_bytes))
    c.drawImage(qr_img, width / 2 - inch, 1.2 * inch, 2 * inch, 2 * inch)

    c.setFont('Helvetica', 8)
    c.drawCentredString(width / 2, 0.8 * inch, 'Scan QR code to verify authenticity')

    c.save()
    buffer.seek(0)
    return buffer.getvalue()


def verify_certificate(certificate_id):
    """
    Verify certificate: fetch from DB, recalculate SHA256 hash, compare with stored.
    Returns dict with: found, certificate, status ('valid' | 'tampered' | 'invalid')
    SQLAlchemy filter_by uses parameterized queries - protects against SQL injection.
    """
    cert = Certificate.query.filter_by(certificate_id=certificate_id).first()
    if cert is None:
        return {'found': False, 'certificate': None, 'status': 'invalid'}

    date_str = cert.issue_date.strftime('%Y-%m-%d %H:%M:%S')
    recalculated_hash = Certificate.generate_hash(
        cert.certificate_id, cert.participant_name, cert.university_id, cert.event_name, date_str
    )
    if recalculated_hash == cert.hash_value:
        return {'found': True, 'certificate': cert, 'status': 'valid'}
    return {'found': True, 'certificate': cert, 'status': 'tampered'}


# ---------- Routes ----------

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """Verify certificate by form input (certificate_id)."""
    result = None
    if request.method == 'POST':
        certificate_id = request.form.get('certificate_id', '').strip()
        result = verify_certificate(certificate_id) if certificate_id else {'found': False, 'certificate': None, 'status': 'invalid'}
    return render_template('verify.html', result=result)


@app.route('/verify/<certificate_id>')
def verify_by_id(certificate_id):
    """Verify certificate by URL (e.g. for QR code scan)."""
    result = verify_certificate(certificate_id)
    return render_template('result.html', result=result)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login using Flask-Login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session.permanent = True
            login_user(admin)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('admin_login.html')


@app.route('/admin/logout')
@login_required
def admin_logout():
    """Admin logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/admin/dashboard')
@login_required
def dashboard():
    """Dashboard page after login."""
    certificates = Certificate.query.order_by(Certificate.issue_date.desc()).all()
    return render_template('dashboard.html', certificates=certificates)


@app.route('/admin/generate', methods=['GET', 'POST'])
@login_required
def generate_certificate():
    """Generate a new certificate."""
    if request.method == 'POST':
        participant_name = request.form.get('participant_name', '').strip()
        university_id = request.form.get('university_id', '').strip()
        event_name = request.form.get('event_name', '').strip()

        if not participant_name or not university_id or not event_name:
            flash('All fields are required.', 'error')
            return render_template('generate_certificate.html')

        # Check if participant already has certificate for this event
        existing = Certificate.query.filter_by(
            participant_name=participant_name,
            university_id=university_id,
            event_name=event_name
        ).first()
        if existing:
            flash('This participant already has a certificate for this event.', 'error')
            return render_template('generate_certificate.html')

        # Generate UUID and check for duplicate (no duplicates allowed)
        certificate_id = str(uuid_module.uuid4())

        if Certificate.query.filter_by(certificate_id=certificate_id).first():
            flash('Duplicate Certificate Detected.', 'error')
            return render_template('generate_certificate.html')

        cert = Certificate.create_certificate(
            participant_name=participant_name,
            university_id=university_id,
            event_name=event_name,
            certificate_id=certificate_id
        )

        db.session.add(cert)
        db.session.commit()

        # Generate and save PDF
        base_url = request.url_root.rstrip('/')
        verification_url = f"{base_url}/verify/{cert.certificate_id}"
        pdf_bytes = create_pdf(cert, verification_url)
        cert_dir = Path(app.config['CERTIFICATES_FOLDER'])
        pdf_filename = f"cert_{cert.certificate_id}.pdf"
        with open(cert_dir / pdf_filename, 'wb') as f:
            f.write(pdf_bytes)

        flash(f'Certificate generated successfully. ID: {cert.certificate_id}', 'success')
        return redirect(url_for('dashboard'))

    return render_template('generate_certificate.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
