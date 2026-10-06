from app import app
from utils.admin_bootstrap import ensure_admin_from_env


def main():
    with app.app_context():
        admin, created = ensure_admin_from_env(reset_password=True)
        action = "Created" if created else "Updated"
        print(f"{action} admin user: {admin.username}")


if __name__ == "__main__":
    main()
