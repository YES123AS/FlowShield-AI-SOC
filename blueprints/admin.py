from flask import Blueprint, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from decorators import admin_required
from extensions import db
from models import Admin, LogModel, TrafficModel, UserModel
from utils.security.auth_guard import (
    is_account_locked,
    lock_message,
    record_login_failure,
    record_login_success
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@admin_required
def index():
    traffics = TrafficModel.query.order_by(TrafficModel.upload_time.desc()).all()
    return render_template("index_admin.html", traffics=traffics)


@admin_bp.route("/logs")
@admin_required
def logs():
    logs = LogModel.query.order_by(LogModel.op_time.desc()).all()
    return render_template("logs_admin.html", logs=logs)


@admin_bp.route("/user_manage", methods=['GET', 'POST'])
@admin_required
def user_manage():
    users = UserModel.query.order_by(UserModel.join_time.desc()).all()
    return render_template("users_admin.html", users=users)


@admin_bp.route("/update_username/<int:user_id>", methods=['GET', 'POST'])
@admin_required
def update_username(user_id):
    new_username = request.form.get('new_username')
    if not new_username:
        return redirect(url_for("admin.index"))
    user = UserModel.query.get(user_id)

    if not user:
        return redirect(url_for("admin.index"))
    user.username = new_username
    try:
        db.session.commit()
        return redirect(url_for("admin.user_manage"))
    except Exception:
        db.session.rollback()
        return redirect(url_for("admin.user_manage"))


@admin_bp.route('/delete_user/<int:id>', methods=['POST'])
@admin_required
def delete_user(id):
    try:
        user = UserModel.query.get(id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return redirect(url_for("admin.user_manage"))
        return redirect(url_for("admin.user_manage"))
    except Exception as e:
        db.session.rollback()
        return f'删除用户时发生错误: {str(e)}', 500


@admin_bp.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login_admin.html")

    username = request.form.get('username')
    password = request.form.get('password')
    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        return render_template("login_admin.html", error="管理员不存在！")
    if is_account_locked(admin):
        return render_template("login_admin.html", error=lock_message(admin), username=username)
    if check_password_hash(admin.password, password):
        session['user_id'] = admin.id
        session['user_role'] = 'admin'
        record_login_success(admin, request.remote_addr)
        return redirect("/admin")

    record_login_failure(admin, request.remote_addr)
    return render_template("login_admin.html", error="密码错误！", username=username)


@admin_bp.route("/logout")
@admin_required
def logout():
    session.clear()
    return redirect("/")
