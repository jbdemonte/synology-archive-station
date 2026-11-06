# Repository Guidelines

## Project Structure & Module Organization

Archive Station is an Internet Archive download manager for Synology DSM 7 and local development. The Python application lives in `src/archive_station/`: `__main__.py` starts Waitress and the background workers, `web.py` exposes the WSGI API, `store.py` persists tasks and files in SQLite, and `engine.py` handles resumable transfers. The browser interface is plain JavaScript, HTML and CSS in `src/archive_station/static/`, with 27 offline JSON language catalogs in `static/locales/`; there is no frontend build step.

Backend tests live in `tests/`; Playwright scenarios and build utilities live in `scripts/`. Synology package resources and the DSM CGI gateway are in `packaging/`. Read `README.md` for setup and usage, `docs/ARCHITECTURE.md` for the design, and `docs/TRANSLATIONS.md` before changing user-facing messages.

## Build, Test, and Development Commands

- `make dev-deps`: create `.venv`, install pinned Python development dependencies and npm packages, and install Playwright Chromium.
- `make run`: install runtime dependencies and start locally on `127.0.0.1:8274`.
- `make check`: run Python unittest discovery, Ruff lint/format checks, Prettier checks and JavaScript syntax checks.
- `make test-ui`: run all browser scenarios against an isolated fixture server on `127.0.0.1:8275`.
- `make format`: apply Ruff and Prettier formatting.
- `make build`: build the standalone x86_64 DSM package in `dist/` (Python 3.12+ and network access required for the initial runtime download).

Use `make test` for backend tests alone. For a focused browser scenario, run `.venv/bin/python scripts/test_ui.py --script scripts/selection_smoke.mjs`. After a Playwright upgrade, `npx playwright install chromium` installs its matching browser revision. Keep `requirements*.txt` and `package-lock.json` consistent with dependency changes.

## Coding Style & Naming Conventions

Python supports 3.10+ and follows the Ruff configuration in `pyproject.toml` (100-character lines). JavaScript, HTML and CSS use Prettier through the scripts in `package.json`. Keep responsibilities in their existing modules and use descriptive names. Translate interface strings through `ArchiveI18n.t()` and keep all 27 catalogs and interpolation tokens in sync.

## Testing Guidelines

Use `unittest`, temporary directories and mocked network responses for deterministic backend tests. Cover failure responses, interrupted transfers and existing destination files when modifying downloads. UI scenarios use Playwright and `tests/serve_ui.py`; they must not download real archives or depend on external services. Some distribution tests require a separately built community package and are skipped when it is absent. Automated checks do not replace testing on a real NAS.

## Commit & Pull Request Guidelines

Use concise, imperative commit subjects and keep commits focused. Review the diff and include only files belonging to the task. Pull requests should describe the change, its purpose and validation performed; link relevant issues, call out configuration changes, and include screenshots for visual changes.

## Security & Configuration

Keep credentials, local configuration, downloaded content and generated output out of version control. Use sanitized configuration examples. Preserve strict Archive.org URL validation, destination path and symlink checks, non-overwriting publication of downloads, and DSM gateway authentication. Document changes to these trust boundaries in `docs/ARCHITECTURE.md` and the README.
