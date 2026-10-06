from functools import wraps
from flask import g, redirect, session, url_for


def login_required(func):
    # 保留func的信息
    @wraps(func)
    # func(a,b,c)
    # func(1,2,c=3)
    def inner(*args, **kwargs):
        if g.user:
            return func(*args, **kwargs)
        else:
            return redirect(url_for("auth.login"))
    return inner


def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if not g.user or session.get("user_role") != "admin":
            return redirect(url_for("admin.login"))
        return func(*args, **kwargs)
    return inner
