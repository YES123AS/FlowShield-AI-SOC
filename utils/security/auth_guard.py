from datetime import datetime, timedelta

from extensions import db


MAX_FAILED_LOGIN = 5
LOCK_MINUTES = 10


def is_account_locked(account):
    locked_until = getattr(account, "locked_until", None)
    return bool(locked_until and locked_until > datetime.utcnow())


def lock_message(account):
    locked_until = getattr(account, "locked_until", None)
    if not locked_until:
        return "账号已被临时锁定，请稍后再试。"
    return f"账号连续登录失败次数过多，已锁定至 {locked_until.strftime('%Y-%m-%d %H:%M:%S')}。"


def record_login_success(account, ip_address):
    account.failed_login_count = 0
    account.locked_until = None
    account.last_login_ip = ip_address
    account.last_login_time = datetime.utcnow()
    db.session.commit()


def record_login_failure(account, ip_address):
    account.failed_login_count = (account.failed_login_count or 0) + 1
    account.last_login_ip = ip_address

    if account.failed_login_count >= MAX_FAILED_LOGIN:
        account.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)

    db.session.commit()
