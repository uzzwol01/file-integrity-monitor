# File Integrity Monitor (FIM)

A command-line tool that detects unauthorized log file tampering using SHA-256 cryptographic hashing. Built with Python.

## What It Does

The tool stores a SHA-256 hash of each monitored file as a baseline. On a later check, it re-hashes the files and compares them to the baseline — any mismatch flags the file as tampered. All actions are recorded to an audit log.

## Features

- **Initialize** a baseline of file hashes for a file or directory
- **Check** monitored files against the baseline to detect tampering
- **Update** a file's stored hash after an authorized change
- **List** all monitored files and their hash metadata
- **Reset** the stored hash database
- Automatic audit logging of every action
- Hash store saved with restrictive (0600) permissions

## Requirements

- Python 3.x (uses only the standard library — no external packages needed)

## Usage

Initialize hashes for a file or directory:

    python integrity_check.py init /var/log

Check files for tampering:

    python integrity_check.py check /var/log

Update a file's hash after an authorized change:

    python integrity_check.py update /var/log/syslog

List all monitored files:

    python integrity_check.py list

Reset all stored hashes:

    python integrity_check.py reset

## How It Works

Each file is hashed with SHA-256 and the hash is stored in a local JSON database (`.integrity_store.json`). During a check, files are re-hashed and compared against the stored values. A mismatch means the file has been altered. Every action is timestamped and written to `integrity_audit.log`.

## Files Created

- `.integrity_store.json` — the hash database (permissions set to 0600)
- `integrity_audit.log` — a log of all init, check, update, and reset actions

## Author

Ujjwal Dhakal
