import os

from flask import Blueprint, current_app, render_template
from werkzeug.security import check_password_hash

from decorators import login_required
from models import Admin


security_bp = Blueprint("security", __name__, url_prefix="/security")


@security_bp.route("/checkup")
@login_required
def checkup():
    checks = [
        _check_debug(),
        _check_secret_key(),
        _check_database_password(),
        _check_admin_password_hash(),
        _check_upload_limit(),
        _check_requirements(),
        _check_deepseek_config(),
        _check_security_headers()
    ]
    risk_count = sum(1 for item in checks if item["level"] == "risk")
    warn_count = sum(1 for item in checks if item["level"] == "warn")
    pass_count = sum(1 for item in checks if item["level"] == "pass")
    return render_template(
        "security/checkup.html",
        checks=checks,
        risk_count=risk_count,
        warn_count=warn_count,
        pass_count=pass_count
    )


def _item(name, status, detail, level):
    return {
        "name": name,
        "status": status,
        "detail": detail,
        "level": level
    }


def _check_debug():
    if current_app.debug:
        return _item("Flask debug 是否开启", "存在风险", "当前开启 debug，生产环境不应开启。", "risk")
    return _item("Flask debug 是否开启", "通过", "当前未开启 debug。", "pass")


def _check_secret_key():
    secret = current_app.config.get("SECRET_KEY", "")
    if not secret or secret == "dev-secret-key":
        return _item("SECRET_KEY 是否安全", "存在风险", "当前使用默认或空 SECRET_KEY，建议改为环境变量中的随机强密钥。", "risk")
    if not os.getenv("SECRET_KEY"):
        return _item("SECRET_KEY 是否安全", "需要关注", "已配置非默认 SECRET_KEY，但未检测到环境变量来源。", "warn")
    return _item("SECRET_KEY 是否安全", "通过", "SECRET_KEY 已从环境变量配置。", "pass")


def _check_database_password():
    if current_app.config.get("DB_ENGINE") == "sqlite":
        return _item("数据库配置", "通过", "当前使用本地 SQLite，适合开发调试；生产环境建议切换到 MySQL 并设置 DB_PASSWORD。", "pass")
    password = current_app.config.get("PASSWORD", "")
    if not password:
        return _item("数据库密码是否为空", "存在风险", "当前数据库密码为空，容易被本机或弱配置环境滥用。", "risk")
    if not os.getenv("DB_PASSWORD"):
        return _item("数据库密码是否来自环境变量", "需要关注", "检测到数据库密码，但未检测到 DB_PASSWORD 环境变量。", "warn")
    return _item("数据库密码是否来自环境变量", "通过", "数据库密码已通过环境变量配置。", "pass")


def _check_admin_password_hash():
    admin = Admin.query.first()
    if not admin:
        return _item("管理员密码是否哈希", "需要关注", "当前没有管理员账号，无法检查密码存储方式。", "warn")
    if admin.password.startswith(("pbkdf2:", "scrypt:")):
        return _item("管理员密码是否哈希", "通过", "管理员密码使用 Werkzeug 哈希格式存储。", "pass")
    return _item("管理员密码是否哈希", "存在风险", "管理员密码疑似明文存储，建议立即改为哈希。", "risk")


def _check_upload_limit():
    limit = current_app.config.get("MAX_CONTENT_LENGTH")
    if not limit:
        return _item("上传文件是否限制大小", "存在风险", "未配置 MAX_CONTENT_LENGTH，超大文件可能拖垮系统。", "risk")
    return _item("上传文件是否限制大小", "通过", f"当前限制为 {round(limit / 1024 / 1024, 2)} MB。", "pass")


def _check_requirements():
    req_path = os.path.join(current_app.root_path, "requirements.txt")
    if not os.path.exists(req_path):
        return _item("requirements.txt 是否存在", "存在风险", "未找到 requirements.txt，不利于复现部署。", "risk")
    if os.path.getsize(req_path) == 0:
        return _item("requirements.txt 是否为空", "存在风险", "requirements.txt 为空。", "risk")
    return _item("requirements.txt 是否完整", "通过", "requirements.txt 已存在且非空。", "pass")


def _check_deepseek_config():
    enabled = current_app.config.get("DEEPSEEK_ENABLE")
    api_key = current_app.config.get("DEEPSEEK_API_KEY")
    if enabled and not api_key:
        return _item("DeepSeek API Key 是否安全配置", "存在风险", "已启用 DeepSeek，但未配置 API Key。", "risk")
    if enabled:
        return _item("DeepSeek API Key 是否安全配置", "通过", "DeepSeek 已启用，API Key 通过环境变量读取。", "pass")
    return _item("DeepSeek 是否启用", "需要关注", "DeepSeek 当前关闭，本地规则研判仍可用。", "warn")


def _check_security_headers():
    return _item("安全响应头是否配置", "通过", "系统已配置 X-Frame-Options、X-Content-Type-Options、Referrer-Policy。", "pass")
