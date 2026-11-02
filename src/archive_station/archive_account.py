"""Internet Archive sessions and opt-in encrypted credentials for automatic renewal."""

import json
import math
import os
import re
import stat
import tempfile
import threading
import time
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__
from .credentials import CredentialError, CredentialVault

LOGIN_URL = "https://archive.org/services/xauthn/?op=login"
COOKIE_NAMES = ("logged-in-user", "logged-in-sig")
UNAVAILABLE = "Connexion Internet Archive indisponible. Réessayer plus tard."
DENIED = (
    "Connexion Internet Archive refusée. Vérifier les identifiants et les autorisations du compte."
)
CHANGED = "Le compte Internet Archive a changé. Réessayer."


class AccountError(ValueError):
    """Safe, translatable message: never expose an authentication response or credential."""

    def __init__(self, message, *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


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
        self.last_refresh = float("-inf")
        self.refresh_error = None
        self.credentials = ""
        self.remember_choice = True
        self.blocked = False
        self.vault = CredentialVault(data_dir)
        self.email, self.cookies, self.expires = "", {}, None
        if self.path is not None:
            self._load()

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
                    value.get("version") not in {1, 2}
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
                credentials = value.get("credentials", "")
                remember_choice = value.get("remember_choice", True)
                blocked = value.get("blocked", False)
                if (
                    not isinstance(credentials, str)
                    or len(credentials) > 32768
                    or type(remember_choice) is not bool
                    or type(blocked) is not bool
                    or (credentials and not remember_choice)
                ):
                    return
                os.fchmod(handle.fileno(), 0o600)
                self.email, self.cookies, self.expires = value["email"], cookies, expires
                self.credentials, self.remember_choice, self.blocked = (
                    credentials,
                    remember_choice,
                    blocked,
                )
                if blocked:
                    self.refresh_error = AccountError(DENIED)
        except (OSError, ValueError, TypeError, KeyError):
            # A corrupt/removed session never prevents the download service starting.
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

    def status(self):
        with self.lock:
            _, cookie = self.snapshot()
            return {
                "connected": bool(cookie),
                "state": "connected" if cookie else "expired" if self.cookies else "disconnected",
                "email": self.email,
                "remember_credentials": bool(self.credentials),
                "remember_choice": self.remember_choice,
                "reconnect_error": str(self.refresh_error) if self.refresh_error else None,
            }

    def _save(
        self, email, cookies, expires, *, credentials=None, remember_choice=None, blocked=None
    ):
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
                        "version": 2,
                        "email": email,
                        "cookies": cookies,
                        "expires": expires,
                        "credentials": self.credentials if credentials is None else credentials,
                        "remember_choice": self.remember_choice
                        if remember_choice is None
                        else remember_choice,
                        "blocked": self.blocked if blocked is None else blocked,
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
                Path(temporary).unlink(missing_ok=True)

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
            if not isinstance(value, dict) or value.get("success") is not True:
                raise AccountError(DENIED)
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
                raise AccountError(DENIED)
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
        ):
            raise AccountError(UNAVAILABLE, retryable=True) from None
        except ValueError as error:
            if isinstance(error, AccountError):
                raise
            raise AccountError(UNAVAILABLE, retryable=True) from None
        return cookies, expires

    def connect(self, email, password, remember=False):
        if (
            not isinstance(email, str)
            or not re.fullmatch(r"[^\s@]{1,128}@[^\s@]{1,125}", email.strip())
            or len(email.strip()) > 254
            or not isinstance(password, str)
            or not 1 <= len(password) <= 4096
            or type(remember) is not bool
        ):
            raise AccountError("Saisir l’e-mail et le mot de passe Internet Archive.")
        if not self.login_lock.acquire(blocking=False):
            raise AccountError("Une connexion est déjà en cours. Réessayer dans quelques instants.")
        try:
            with self.lock:
                if time.monotonic() - self.last_attempt < 5:
                    raise AccountError(
                        "Une connexion est déjà en cours. Réessayer dans quelques instants."
                    )
                self.last_attempt = time.monotonic()
                generation = self.generation
            cookies, expires = self._login(email, password)
            with self.lock:
                if self.generation != generation:
                    raise AccountError(CHANGED)
                try:
                    credentials = self.vault.encrypt(email.strip(), password) if remember else ""
                except CredentialError as error:
                    raise AccountError(str(error)) from None
                self._save(
                    email.strip(),
                    cookies,
                    expires,
                    credentials=credentials,
                    remember_choice=remember,
                    blocked=False,
                )
                self.email, self.cookies, self.expires = email.strip(), cookies, expires
                self.credentials, self.remember_choice = credentials, remember
                self.blocked, self.refresh_error = False, None
                self.last_refresh = float("-inf")
                self.generation += 1
                self.account_generation = self.generation
                if not remember:
                    self.vault.forget()
            return self.status()
        finally:
            self.login_lock.release()

    def request_snapshot(self):
        """Renew an expired saved session only when a request actually needs it."""
        identity, cookie = self.snapshot()
        if not cookie:
            self.refresh(identity, expired=True)
        return self.snapshot()

    def refresh(self, identity, *, expired=False):
        """Single-flight renewal, at most once per minute and never after logout.

        HTTP 403 can also mean a genuine lack of permission: callers retry their
        original request only once, and a second denial remains a file error.
        """
        with self.lock:
            if not self.credentials or identity[0] < self.account_generation:
                return False
        if not self.login_lock.acquire(timeout=20):
            raise AccountError(UNAVAILABLE, retryable=True)
        try:
            with self.lock:
                if not self.credentials or identity[0] < self.account_generation:
                    return False
                current, cookie = self.snapshot()
                if current != identity and cookie:
                    return True  # Another worker has already renewed this session.
                if self.blocked:
                    if expired:
                        raise self.refresh_error or AccountError(DENIED)
                    return False
                if time.monotonic() - self.last_refresh < 60:
                    if self.refresh_error:
                        raise self.refresh_error
                    if expired:
                        raise AccountError(UNAVAILABLE, retryable=True)
                    return False
                self.last_refresh = time.monotonic()
                generation, email, token = self.generation, self.email, self.credentials
            try:
                password = self.vault.decrypt(token, email)
                try:
                    cookies, expires = self._login(email, password)
                finally:
                    password = None
            except (AccountError, CredentialError) as error:
                safe = error if isinstance(error, AccountError) else AccountError(str(error))
                with self.lock:
                    if self.generation != generation:
                        return False
                    self.refresh_error = safe
                    self.blocked = not safe.retryable
                    # Persist invalid-credential rejection so a restart cannot
                    # repeatedly submit an incorrect password and lock the account.
                    if self.blocked:
                        self._save(self.email, self.cookies, self.expires)
                raise safe from None
            with self.lock:
                if self.generation != generation:
                    return False
                self._save(email, cookies, expires, blocked=False)
                self.cookies, self.expires = cookies, expires
                self.blocked, self.refresh_error = False, None
                self.generation += 1
            return True
        finally:
            self.login_lock.release()

    def forget_credentials(self):
        with self.lock:
            self._save(
                self.email,
                self.cookies,
                self.expires,
                credentials="",
                remember_choice=False,
                blocked=False,
            )
            self.credentials, self.remember_choice = "", False
            self.blocked, self.refresh_error = False, None
            self.vault.forget()
            self.generation += 1
            self.account_generation = self.generation
            return self.status()

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
            self.credentials, self.remember_choice = "", True
            self.blocked, self.refresh_error = False, None
            self.vault.forget()
            self.generation += 1
            self.account_generation = self.generation
            return self.status()
