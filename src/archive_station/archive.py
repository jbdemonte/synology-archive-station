"""Internet Archive metadata and validated download locations."""

import fnmatch
import json
import re
import threading
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__
from .archive_account import CHANGED, AccountError, ArchiveAccount

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
USER_AGENT = f"ArchiveStation/{__version__} (personal archive downloader)"


def parse_identifier(value):
    if not isinstance(value, str):
        raise ValueError("Saisissez une URL Archive.org.")
    value = value.strip()
    if "://" in value:
        url = urlsplit(value)
        if (
            url.scheme not in {"https", "http"}
            or url.hostname not in {"archive.org", "www.archive.org"}
            or url.username
            or url.port
        ):
            raise ValueError("L’URL doit appartenir à archive.org.")
        parts = url.path.strip("/").split("/")
        if len(parts) < 2 or parts[0] not in {"details", "download", "metadata"}:
            raise ValueError("Utilisez une URL /details/ ou /download/ d’un élément Archive.org.")
        value = unquote(parts[1])
    if not IDENTIFIER.fullmatch(value) or value in {".", ".."}:
        raise ValueError("Identifiant Archive.org invalide.")
    return value


def validate_name(name):
    if (
        not isinstance(name, str)
        or not name
        or "\\" in name
        or any(ord(c) < 32 for c in name)
        or any(p in {"", ".", ".."} for p in name.split("/"))
        or any(len(p.encode()) > 255 for p in name.split("/"))
    ):
        raise ValueError(f"Chemin de fichier non autorisé : {name!r}")
    return name


def safe_path(root, relative):
    """Reject traversal and existing symlinks, including links inside the destination."""
    validate_name(relative)
    root = Path(root).resolve()
    current = root
    for part in relative.split("/"):
        current /= part
        if current.is_symlink():
            raise ValueError("Un lien symbolique se trouve dans le chemin de destination.")
    if not current.resolve().is_relative_to(root):
        raise ValueError("Le chemin sort du dossier de destination.")
    return current


class ArchiveRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urlsplit(newurl)
        host = url.hostname or ""
        if (
            url.scheme != "https"
            or url.username
            or url.port not in {None, 443}
            or not (host == "archive.org" or host.endswith(".archive.org"))
        ):
            raise ValueError("Redirection hors d’Archive.org refusée.")
        if url.path.startswith(("/account/", "/services/xauthn")):
            if fp is not None:
                fp.close()
            raise HTTPError(newurl, 403, "Internet Archive authorization required", headers, None)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ArchiveClient:
    def __init__(self, account=None):
        self.lock = threading.Lock()
        self.cache = {}
        self.account = account or ArchiveAccount()
        self.cache_identity = (self.account.identity(), bool(self.account.snapshot()[1]))

    def clear_cache(self):
        with self.lock:
            self.cache.clear()
            self.cache_identity = (self.account.identity(), bool(self.account.snapshot()[1]))

    def _open(self, url, *, timeout, session=None, offset=0):
        identity, cookie = session or self.account.request_snapshot()
        for attempt in range(2):
            headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
            if cookie:
                headers["Cookie"] = cookie
            if offset:
                headers["Range"] = f"bytes={offset}-"
            try:
                response = build_opener(ArchiveRedirects()).open(
                    Request(url, headers=headers), timeout=timeout
                )
                final_url = getattr(response, "url", url)
                if isinstance(final_url, str) and urlsplit(final_url).path.startswith(
                    ("/account/", "/services/xauthn")
                ):
                    response.close()
                    raise HTTPError(url, 403, "Internet Archive authorization required", {}, None)
                return response, identity, cookie
            except HTTPError as error:
                if attempt or error.code not in {401, 403}:
                    raise
                try:
                    session_changed = self.account.refresh(identity)
                except Exception:
                    error.close()
                    raise
                if not session_changed:
                    raise
                error.close()
                identity, cookie = self.account.snapshot()

    def open(self, identifier, name, offset=0):
        url = f"https://archive.org/download/{quote(identifier)}/{quote(name, safe='/')}"
        # Repeat the same Range after a new manual login; no bytes are published before
        # authentication, length and checksum validation by the transfer engine.
        response, _, _ = self._open(url, timeout=30, offset=offset)
        return response

    def manifest(self, identifier, mode="all", pattern="", refresh=False):
        if mode not in {"all", "original"}:
            raise ValueError("Sélection de fichiers invalide.")
        if not isinstance(pattern, str) or len(pattern) > 200:
            raise ValueError("Filtre trop long.")
        account_identity = self.account.identity()
        identity, cookie = self.account.request_snapshot()
        cache_identity = (account_identity, bool(cookie))
        with self.lock:
            if self.cache_identity != cache_identity:
                self.cache.clear()
                self.cache_identity = cache_identity
            cached = self.cache.get(identifier)
        if cached and not refresh and time.monotonic() - cached[0] < 900:
            payload = cached[1]
        else:
            response, identity, cookie = self._open(
                f"https://archive.org/metadata/{identifier}",
                timeout=45,
                session=(identity, cookie),
            )
            with response:
                raw = response.read(64 * 1024 * 1024 + 1)
            if len(raw) > 64 * 1024 * 1024:
                raise ValueError("La liste des fichiers dépasse la limite de 64 Mo.")
            payload = json.loads(raw)
            if not isinstance(payload, dict) or not payload.get("files"):
                raise ValueError("Élément introuvable, privé ou sans fichiers téléchargeables.")
            with self.lock:
                if self.account.identity() != account_identity:
                    raise AccountError(CHANGED)
                cache_identity = (account_identity, bool(cookie))
                if self.cache_identity != cache_identity:
                    self.cache.clear()
                    self.cache_identity = cache_identity
                if len(self.cache) >= 4:
                    self.cache.pop(next(iter(self.cache)))
                self.cache[identifier] = (time.monotonic(), payload)
        files, seen, private, restricted = [], set(), 0, 0
        for item in payload["files"]:
            name = item.get("name")
            if mode == "original" and item.get("source") != "original":
                continue
            if pattern and (not isinstance(name, str) or not fnmatch.fnmatchcase(name, pattern)):
                continue
            is_private = item.get("private") in {True, "true", "1"}
            if is_private and not cookie:
                private += 1
                continue
            name = validate_name(name)
            if name in seen:
                continue
            seen.add(name)
            restricted += is_private
            size = int(item["size"]) if item.get("size") is not None else None
            if size is not None and size < 0:
                raise ValueError("Taille de fichier invalide dans les métadonnées.")
            # The files.xml 'summation' checksum describes its entries, not its own bytes.
            algorithm, digest = None, None
            if not item.get("summation"):
                for key, length in (("sha1", 40), ("md5", 32)):
                    value = item.get(key, "")
                    if isinstance(value, str) and re.fullmatch(rf"[a-fA-F0-9]{{{length}}}", value):
                        algorithm, digest = key, value.lower()
                        break
            files.append({"name": name, "size": size, "algorithm": algorithm, "digest": digest})
        if not files:
            raise ValueError("Aucun fichier public ne correspond à cette sélection.")
        # Reject file/directory collisions before starting any transfer.
        for name in seen:
            parts = name.split("/")
            if any("/".join(parts[:i]) in seen for i in range(1, len(parts))):
                raise ValueError("La liste contient un conflit entre fichier et dossier.")
        title = payload.get("metadata", {}).get("title", identifier)
        if isinstance(title, list):
            title = " / ".join(
                value.strip() for value in title if isinstance(value, str) and value.strip()
            )
        if isinstance(title, str):
            title = title.strip()
        title = title or identifier
        if self.account.identity() != account_identity:
            raise AccountError(CHANGED)
        return {
            "identifier": identifier,
            "account_generation": account_identity,
            "title": str(title),
            "files": files,
            "total_size": sum(f["size"] or 0 for f in files),
            "unknown_sizes": sum(f["size"] is None for f in files),
            "private_files": private,
            "restricted_files": restricted,
        }
