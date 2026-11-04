# Queue management and archive maintenance

These controls are available in **Settings** and in each task’s **⋯** menu, at the end of its row.

The toolbar acts on the selected archive or checked rows. The **⋯** menu always acts on its own archive, regardless of the toolbar selection. It stays open during progress updates; Escape closes it, and arrow keys move between its actions.

![Per-archive action menu](images/actions.png)

## Connect an Internet Archive account

Open **Settings → Internet Archive account → Log in**, then enter your Internet Archive email and password. Public downloads work without an account. Use DSM over HTTPS when entering account credentials.

![Internet Archive account connection dialog](images/archive-account.png)

**Remember credentials to reconnect automatically** is checked by default. When enabled, Archive Station encrypts the password and renews an expired or rejected session as needed, without asking you to sign in again. An existing session from an earlier version is preserved, but you must enter your password once to enable automatic reconnection: the old version did not save it.

Uncheck the option when signing in to retain only the session. In Settings, **Forget password** removes the saved credentials while keeping the current session and transfers active. **Disconnect** removes both the saved session and credentials; transfers already open may finish, while later requests use public access.

Passwords are sent only to Internet Archive over HTTPS. Saved passwords use authenticated [Fernet encryption](https://cryptography.io/en/stable/fernet/). The ciphertext, account email and session cookies live in `archive-account.json`; the randomly generated local key lives in `archive-account.key`. Both files are in the package data directory with owner-only permissions (`0600`) and survive restarts and upgrades. Email and session cookies are not encrypted. The key must remain available to the service, so encryption does not protect against an administrator or attacker who can read both files. Protect backups of these files as account credentials; forgetting a password does not erase older backups.

The account is shared by the DSM administrators using this installation. The settings API and download reports never contain the password, encrypted credentials, key or cookies. S3 keys returned by Internet Archive are discarded.

Without a connected account, analysis highlights how many restricted files were excluded. With an account, these files are included in the selection and their authorization is checked when downloaded. An account does not grant access to every locked file. On an authentication failure, Archive Station renews the session once and repeats the same download range; a second denial remains a file error. Concurrent transfers share one renewal, limited to once per minute. Incorrect saved credentials disable automatic attempts until you reconnect the account; public requests fall back to anonymous access if renewal fails. Restricted downloads wait for the shared login cooldown without consuming file attempts; actual failed renewal requests remain retryable. Local key errors and clock skew do not persist a rejected-password state. No completed file is published before the configured integrity checks pass.

For an existing task that contains only public metadata files:

1. Connect your Internet Archive account.
2. Pause the task if it is running and wait for active transfers to stop.
3. Choose **⋯ → Refresh file list**, review the additional files and apply the selection.
4. Resume the task as needed. Files already downloaded are retained.

Account changes invalidate pending file selections; routine session renewal preserves them. After changing accounts, analyze the URLs again before adding a task. No account password is required to open Archive Station itself: access to the application still uses your DSM session.

## Receive DSM desktop notifications

Receive alerts for task completion, persistent file errors and low disk space, even with the window closed. Disable them in Settings. Alerts go to DSM administrators and survive service restarts without duplicates.

## Schedule transfers

Choose weekdays and one daily time slot using the NAS clock; pause or apply an alternate speed limit outside it. Overnight slots belong to their starting day. Equal start/end times mean a full day. Manual pauses remain paused.

## Prioritize the queue

Set archive priority and move tasks within that priority. Star queued files to transfer them first within their archive. In-flight transfers finish normally.

## Protect free disk space

Keep a configurable reserve (1 GiB by default). The add dialog compares selected known sizes against free space minus the reserve and queued transfers on the same filesystem. Oversized tasks can be added paused. Low space during a transfer pauses the task; free space and resume it to continue. Unknown file sizes and external disk writes cannot be reserved in advance.

## Verify and complete an archive

Pause a task and wait for active transfers to stop, then recheck its files. Available checksums are always used for this operation, even if routine verification is disabled. Valid files are reused; missing or corrupt files are fetched again. Replaced copies are preserved under `.archive-station-replaced/<task-id>/<backup-id>/`, with their original relative paths. Without a checksum, only size can be verified.

## Control multiple tasks

Check archives or select all visible rows, then use the toolbar. Global actions pause all active tasks, resume paused tasks, or remove completed tasks while preserving their files. Search and filters clear hidden selections.

## Inspect recent throughput

Expand **Transfer history** and choose **1 h, 6 h, 12 h or 24 h** in **Period**. The 120 points average 30 seconds, 3 minutes, 6 minutes or 12 minutes, respectively. Hover for interval details. The browser remembers your choice. The NAS retains up to 24 hours of measurements independently of browser polling, checkpoints changed traffic every 30 seconds and saves at orderly shutdown. The graph survives package restarts and upgrades; forced termination can lose recent unsaved graph samples. Remaining-time estimates use their own five-minute average and warm up again after restarting.

![Transfer history with a 24-hour period selector](images/history.png)

## Refresh an archive

Fetch fresh metadata and review new or changed files before applying a selection to a stopped task. Initial exclusions stay excluded for new tasks; files absent from the source stay on disk. Changed files and obsolete partials are backed up before replacement. Metadata comparisons use available sizes/checksums; they cannot detect changes missing from the remote metadata.

## Open the destination in File Station

Choose **⋯ → Open in File Station** on an archive to open its folder inside DSM. If the item folder has not been created yet, its parent destination opens instead. The external-link icon beside **⋯** opens the archive's source page in a browser tab.

Pause and wait for active workers to stop before applying a metadata refresh or starting verification. Existing downloads and excluded files in older tasks remain intact during upgrades. For tasks created before file-selection tracking was introduced, refresh treats files absent from the saved task as new candidates.

## Read the report and error history

Click the document icon on an archive row, or **Read report** in its **⋯** menu, to read an up-to-date report inside Archive Station. The same report is written to `ArchiveStation-report-<task-id>.txt` in the archive folder. Long reports are paginated in the reader; the text file contains the entire history.

**Source file mode** describes the file-type filter: **Original files only** or **All accessible files**, including derived files. It does not describe access permissions: restricted files can be included when your Internet Archive account is authorized. Filename filters and manual selection can further limit the downloaded files.

**Completed file integrity** counts the checks actually performed: matching SHA-1, matching MD5, size only, no reference check, and checks not recorded by older versions. Results are saved with each completed file and survive restarts and settings changes. An in-progress or failed file is never counted as hash verified. The report also shows the last recorded check date. Without a usable checksum or expected size, a completed transfer cannot establish integrity against a reference. A size merely observed on disk never becomes a source reference when running Verify and complete. Older size-only results without recorded size provenance become Check not recorded on upgrade.

Files completed before this tracking was introduced remain **Check not recorded**; the current setting cannot prove which checks ran earlier. **Verify and complete** can check them and record the result. This recheck reads the files from disk and is never started automatically by an upgrade. Recorded results describe the file at completion, not a continuous check for later disk corruption or external changes.

The icon turns amber when incidents have been recorded, including incidents that were later resolved. The history lists the affected file, first and last occurrence, count, latest attempt number, diagnostic message and resolution date. Repeated identical errors are grouped per file. A successful transfer resolves its recorded errors; retrying, restarting or repairing does not erase them. Low-space pauses are also recorded.

History starts when this feature is installed. An existing error can be imported without a known date, but errors already cleared by older versions cannot be recovered. The reader works even if the destination is temporarily unavailable; writing the disk copy still requires permission to that folder.

Reports are available in French when the interface is French, and in English for other languages. Automatic mode uses the last resolved DSM language with the same fallback. A language change updates the disk report at the next check, approximately every 15 seconds; use **Refresh** in an open reader. Recorded technical error messages retain their original text.
