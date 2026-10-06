import os

import config
from flask import Flask, g, session
from flask_migrate import Migrate

from blueprints.analysis import analysis_bp
from blueprints.admin import admin_bp
from blueprints.auth import bp as auth_bp
from blueprints.security_check import security_bp
from blueprints.soc import soc_bp
from blueprints.qa import bp as qa_bp
from extensions import db
from models import Admin, UserModel
from utils.admin_bootstrap import ensure_admin_from_env


app = Flask(__name__)
app.config.from_object(config)

db.init_app(app)

migrate = Migrate(app, db)
app.register_blueprint(qa_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(analysis_bp)
app.register_blueprint(soc_bp)
app.register_blueprint(security_bp)

_database_initialized = False
_admin_initialized = False


def _ensure_local_sqlite_tables():
    global _database_initialized
    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if _database_initialized or not app.config.get("AUTO_CREATE_TABLES"):
        return
    if not db_uri.startswith("sqlite:///"):
        return
    db.create_all()
    _database_initialized = True


def _ensure_admin_account():
    global _admin_initialized
    if _admin_initialized:
        return
    if os.getenv("AUTO_CREATE_ADMIN", "false").lower() != "true":
        _admin_initialized = True
        return
    ensure_admin_from_env(reset_password=False)
    _admin_initialized = True


@app.before_request
def my_before_request():
    _ensure_local_sqlite_tables()
    _ensure_admin_account()
    user_id = session.get("user_id")
    if user_id:
        role = session.get("user_role")
        if role == "admin":
            user = Admin.query.get(user_id)
        elif role == "user":
            user = UserModel.query.get(user_id)
        else:
            user = UserModel.query.get(user_id)
            if not user:
                user = Admin.query.get(user_id)
        setattr(g, "user", user)
    else:
        setattr(g, "user", None)

@app.context_processor
def my_context_processor():
    return {"user": getattr(g, "user", None)}


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


if __name__ == '__main__':
    app.run(debug=True, port=5001)
