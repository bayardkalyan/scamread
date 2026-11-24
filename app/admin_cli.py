"""Admin account helper, run on the server:

    cd /opt/scamread
    sudo -u scamread venv/bin/python -m app.admin_cli set-password BAYARD
    venv/bin/python -m app.admin_cli hash          # print a hash for /etc/scamread.env
    sudo -u scamread venv/bin/python -m app.admin_cli list
"""

import getpass
import sys

from app.services import admin_auth
from app.services.database import get_connection


def _ask_new_password() -> str:
    first = getpass.getpass("New password: ")
    if getpass.getpass("Type it again: ") != first:
        sys.exit("The two passwords are different.")
    if len(first) < admin_auth.MIN_PASSWORD_LENGTH:
        sys.exit(f"Use at least {admin_auth.MIN_PASSWORD_LENGTH} characters.")
    return first


def main(argv: list[str]) -> None:
    if not argv or argv[0] not in {"hash", "set-password", "list"}:
        sys.exit(__doc__)
    if argv[0] == "hash":
        print(admin_auth.hash_password(_ask_new_password()))
    elif argv[0] == "set-password":
        if len(argv) != 2:
            sys.exit("Usage: python -m app.admin_cli set-password USERNAME")
        admin_auth.set_password(argv[1], _ask_new_password())
        print(f"Password set for {argv[1]}. All their sessions were logged out.")
    else:
        for row in get_connection().execute("SELECT username, created_at, password_changed_at FROM admin_users"):
            print(row["username"], "created", row["created_at"][:10], "password changed", row["password_changed_at"][:10])


if __name__ == "__main__":
    main(sys.argv[1:])
