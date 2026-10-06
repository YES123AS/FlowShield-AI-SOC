import os

from werkzeug.security import generate_password_hash

from extensions import db
from models import Admin


def ensure_admin_from_env(reset_password=False):
    """Create the configured administrator and optionally reset its password."""
    username = os.getenv("ADMIN_USERNAME", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not username or not password:
        raise ValueError("ADMIN_USERNAME 和 ADMIN_PASSWORD 不能为空")

    admin = Admin.query.filter_by(username=username).first()
    created = admin is None
    if created:
        admin = Admin(username=username, password=generate_password_hash(password))
        db.session.add(admin)
    elif reset_password:
        admin.password = generate_password_hash(password)

    if created or reset_password:
        admin.failed_login_count = 0
        admin.locked_until = None
        db.session.commit()

    return admin, created
