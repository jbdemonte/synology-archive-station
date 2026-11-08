"""Internet Archive sessions, persisted without account passwords."""

import json
import math
import os
import re
import stat
import tempfile
import threading
import time
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__

LOGIN_URL = "https://archive.org/services/xauthn/?op=login"
COOKIE_NAMES = ("logged-in-user", "logged-in-sig")
UNAVAILABLE = "Connexion Internet Archive indisponible. Réessayer plus tard."
DENIED = (
    "Connexion Internet Archive refusée. Vérifier les identifiants et les autorisations du compte."
)
CHANGED = "Le compte Internet Archive a changé. Réessayer."


class AccountError(ValueError):
    """Safe, translatable message: never expose an authentication response or credential."""

    def __init__(self, message, *, retryable=False, retry_after=None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


class NoLoginRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if fp is not None:
            fp.close()
        raise AccountError(UNAVAILABLE, retryable=True)


class ArchiveAccount:
    def __init__(self, data_dir=None, clock=time.time):
        self.path = Path(data_dir) / "archive-account.json" if data_dir is not None else None
        self.clock = clock
        self.lock = threading.RLock()
        self.login_lock = threading.Lock()
        self.generation = 0
        self.account_generation = 0
        self.last_attempt = float("-inf")
        self.email, self.cookies, self.expires = "", {}, None
        if self.path is not None:
            self._load()
            self._remove_legacy_key()

    def _load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "r") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    return
                raw = handle.read(65537)
                if len(raw) > 65536:
                    return
                value = json.loads(raw)
                cookies = value["cookies"]
                expires = value.get("expires")
                if (
                    value.get("version") not in {1, 2, 3, 4}
                    or not isinstance(value.get("email"), str)
                    or len(value["email"]) > 254
                    or not isinstance(cookies, dict)
                    or set(cookies) != set(COOKIE_NAMES)
                    or any(not self._valid_cookie(v) for v in cookies.values())
                    or (
                        expires is not None
                        and (
                            type(expires) not in {float, int}
                            or not math.isfinite(expires)
                            or expires <= 0
                        )
                    )
                ):
                    return
                self.email, self.cookies, self.expires = value["email"], cookies, expires
                repair_permissions = False
                try:
                    os.fchmod(handle.fileno(), 0o600)
                except OSError:
                    repair_permissions = True
            if (
                repair_permissions
                or value["version"] != 4
                or any(
                    name in value
                    for name in ("credentials", "remember_choice", "blocked", "blocked_reason")
                )
            ):
                # Discard old ciphertext without decrypting it. A read-only state
                # directory must not prevent using the validated session in memory.
                self._save(self.email, self.cookies, self.expires)
        except (OSError, ValueError, TypeError, KeyError):
            # A corrupt/removed session never prevents the download service starting.
            pass

    def _remove_legacy_key(self):
        if self.path is not None:
            try:
                # unlink removes a symlink itself, never its target.
                self.path.with_name("archive-account.key").unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _valid_cookie(value):
        return (
            isinstance(value, str)
            and 1 <= len(value) <= 4096
            and all(33 <= ord(c) <= 126 and c not in '",;\\' for c in value)
        )

    def snapshot(self):
        with self.lock:
            active = bool(self.cookies) and (self.expires is None or self.expires > self.clock())
            cookie = (
                "; ".join(f"{name}={self.cookies[name]}" for name in COOKIE_NAMES) if active else ""
            )
            return (self.generation, active), cookie

    def identity(self):
        """Account identity for selections; changes on manual login and logout."""
        with self.lock:
            return self.account_generation

    def status(self):
        with self.lock:
            _, cookie = self.snapshot()
            return {
                "connected": bool(cookie),
                "state": "connected" if cookie else "expired" if self.cookies else "disconnected",
                "email": self.email,
            }

    def _save(self, email, cookies, expires):
        if self.path is None:
            return
        temporary = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".archive-account-", dir=self.path.parent)
            with os.fdopen(fd, "w") as handle:
                os.fchmod(handle.fileno(), 0o600)
                json.dump(
                    {
                        "version": 4,
                        "email": email,
                        "cookies": cookies,
                        "expires": expires,
                    },
                    handle,
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except OSError:
            raise AccountError(
                "Impossible d’enregistrer la session Internet Archive.", retryable=True
            ) from None
        finally:
            if temporary is not None:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError:
                    pass

    def _login(self, email, password):
        request = Request(
            LOGIN_URL,
            data=urlencode({"email": email.strip(), "password": password}).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": f"ArchiveStation/{__version__}",
            },
        )
        try:
            with build_opener(NoLoginRedirects()).open(request, timeout=15) as response:
                raw = response.read(65537)
            if len(raw) > 65536:
                raise AccountError(UNAVAILABLE, retryable=True)
            value = json.loads(raw)
            if isinstance(value, dict) and value.get("success") is False:
                raise AccountError(DENIED)
            if not isinstance(value, dict) or value.get("success") is not True:
                raise AccountError(UNAVAILABLE, retryable=True)
            supplied = value["values"]["cookies"]
            cookies, expiries = {}, []
            for name in COOKIE_NAMES:
                raw_cookie = supplied[name]
                if (
                    not isinstance(raw_cookie, str)
                    or len(raw_cookie) > 8192
                    or any(ord(c) < 32 for c in raw_cookie)
                ):
                    raise AccountError(UNAVAILABLE, retryable=True)
                parsed = SimpleCookie()
                parsed.load(f"{name}={raw_cookie}")
                morsel = parsed[name]
                if not self._valid_cookie(morsel.value):
                    raise AccountError(UNAVAILABLE, retryable=True)
                cookies[name] = morsel.value
                if morsel["max-age"]:
                    expiries.append(self.clock() + int(morsel["max-age"]))
                elif morsel["expires"]:
                    expiries.append(parsedate_to_datetime(morsel["expires"]).timestamp())
            expires = min(expiries) if expiries else None
            if expires is not None and expires <= self.clock():
                raise AccountError(UNAVAILABLE, retryable=True)
        except HTTPError as error:
            code = error.code
            error.close()
            raise AccountError(
                DENIED if code in {401, 403} else UNAVAILABLE, retryable=code not in {401, 403}
            ) from None
        except (
            URLError,
            OSError,
            TimeoutError,
            KeyError,
            TypeError,
            CookieError,
            UnicodeError,
            HTTPException,
        ):
            raise AccountError(UNAVAILABLE, retryable=True) from None
        except ValueError as error:
            if isinstance(error, AccountError):
                raise
            raise AccountError(UNAVAILABLE, retryable=True) from None
        return cookies, expires

    def connect(self, email, password):
        if (
            not isinstance(email, str)
            or not re.fullmatch(r"[^\s@]{1,128}@[^\s@]{1,125}", email.strip())
            or len(email.strip()) > 254
            or not isinstance(password, str)
            or not 1 <= len(password) <= 4096
        ):
            raise AccountError("Saisir l’e-mail et le mot de passe Internet Archive.")
        if not self.login_lock.acquire(blocking=False):
            raise AccountError("Une connexion est déjà en cours. Réessayer dans quelques instants.")
        try:
            with self.lock:
                if time.monotonic() - self.last_attempt < 5:
                    raise AccountError(
                        UNAVAILABLE,
                        retryable=True,
                        retry_after=5 - (time.monotonic() - self.last_attempt),
                    )
                self.last_attempt = time.monotonic()
                generation = self.generation
            cookies, expires = self._login(email, password)
            with self.lock:
                if self.generation != generation:
                    raise AccountError(CHANGED)
                self._save(email.strip(), cookies, expires)
                self.email, self.cookies, self.expires = email.strip(), cookies, expires
                self.generation += 1
                self.account_generation = self.generation
                self._remove_legacy_key()
            return self.status()
        finally:
            self.login_lock.release()

    def request_snapshot(self):
        """Expired sessions use public access until the user logs in again."""
        return self.snapshot()

    def refresh(self, identity):
        """Retry a denied request only after a newer manual login; never log in here."""
        with self.lock:
            current, cookie = self.snapshot()
            return bool(cookie) and current[0] > identity[0]

    def disconnect(self):
        with self.lock:
            if self.path is not None:
                try:
                    self.path.unlink(missing_ok=True)
                except OSError:
                    raise AccountError(
                        "Impossible d’enregistrer la session Internet Archive."
                    ) from None
            self.email, self.cookies, self.expires = "", {}, None
            self._remove_legacy_key()
            self.generation += 1
            self.account_generation = self.generation
            return self.status()
