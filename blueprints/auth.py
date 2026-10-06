from flask import Blueprint, redirect, render_template, request, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

from blueprints.forms import RegisterForm, LoginForm
from extensions import db
from models import UserModel
from utils.security.auth_guard import (
    is_account_locked,
    lock_message,
    record_login_failure,
    record_login_success
)

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")
    else:
        form = LoginForm(request.form)
        if form.validate():
            username = form.username.data
            password = form.password.data
            user = UserModel.query.filter_by(username=username).first()
            if not user:
                print("用户名在数据库中不存在！")
                return render_template("login.html", error="用户不存在！")
            if is_account_locked(user):
                return render_template("login.html", error=lock_message(user), username=username)
            if check_password_hash(user.password, password):
                # cookie：
                # cookie中不适合存储太多的数据，只适合存储少量的数据
                # cookie一般用来存放登录授权的东西
                # flask中的session，是经过加密后存储在cookie中的
                session['user_id'] = user.id
                session['user_role'] = 'user'
                record_login_success(user, request.remote_addr)
                return redirect("/")
            else:
                print("密码错误！")
                record_login_failure(user, request.remote_addr)
                return render_template("login.html", error="密码错误！", username=username)
        else:
            print(form.errors)
            username = form.username.data
            password = form.password.data
            if password == "":
                return render_template("login.html", error="密码不能为空！", username=username)
            elif len(password)> 0:
                return render_template("login.html", error="用户名或密码格式错误！", username=username)
            else:
                return render_template("login.html", error="用户名格式错误！")

@bp.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    else:
        form = RegisterForm(request.form)
        if form.validate():
            username = form.username.data
            password = form.password.data
            user = UserModel(username=username, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("auth.login"))
        else:
            print(form.errors)
            return redirect(url_for("auth.register"))

@bp.route("/logout")
def logout():
    session.clear()
    return redirect("/")
