"""Authenticated encryption for optional saved Internet Archive credentials."""

import json
import os
import stat
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

STORAGE_ERROR = (
    "Impossible de lire ou d’enregistrer les identifiants mémorisés. Reconnecter le compte."
)


class CredentialError(ValueError):
    pass


class CredentialVault:
    def __init__(self, data_dir=None):
        self.path = Path(data_dir) / "archive-account.key" if data_dir is not None else None
        self.memory_key = None

    def _key(self, create=False):
        if self.path is None:
            if self.memory_key is None and create:
                self.memory_key = Fernet.generate_key()
            if self.memory_key is None:
                raise ValueError("Missing key")
            return self.memory_key
        if create and not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".archive-account-key-", dir=self.path.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    os.fchmod(handle.fileno(), 0o600)
                    handle.write(Fernet.generate_key())
                    handle.flush()
                    os.fsync(handle.fileno())
                # Never replace an existing key: a second writer must use that key.
                try:
                    os.link(temporary, self.path)
                except FileExistsError:
                    pass
            finally:
                Path(temporary).unlink(missing_ok=True)
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise ValueError("Invalid key file")
            key = handle.read(45)
            if len(key) != 44:
                raise ValueError("Invalid key")
            os.fchmod(handle.fileno(), 0o600)
            return key

    def encrypt(self, email, password):
        try:
            data = json.dumps({"email": email, "password": password}, ensure_ascii=False).encode()
            return Fernet(self._key(create=True)).encrypt(data).decode("ascii")
        except (OSError, ValueError, TypeError):
            raise CredentialError(STORAGE_ERROR) from None

    def decrypt(self, token, email):
        try:
            value = json.loads(Fernet(self._key()).decrypt(token.encode("ascii")))
            if (
                not isinstance(value, dict)
                or value.get("email") != email
                or not isinstance(value.get("password"), str)
                or not 1 <= len(value["password"]) <= 4096
            ):
                raise ValueError("Invalid credentials")
            return value["password"]
        except (OSError, ValueError, TypeError, KeyError, InvalidToken):
            raise CredentialError(STORAGE_ERROR) from None

    def forget(self):
        self.memory_key = None
        if self.path is not None:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                # The account file no longer contains ciphertext; a key alone
                # cannot reconnect. Backups remain subject to their retention policy.
                pass
