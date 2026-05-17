#!/usr/bin/env python3
"""
integrity_check.py — File Integrity Monitoring Tool
-----------------------------------------------------
Author: Ujjwal Dhakal
Description: A command-line tool that uses SHA-256 cryptographic hashing
             to detect unauthorized tampering in log files. Supports
             initialization, integrity checking, and hash updates.

Usage:
    python integrity_check.py init <path>          # Initialize hashes
    python integrity_check.py check <path>         # Check integrity
    python integrity_check.py update <path>        # Update hash for a file
    python integrity_check.py list                 # List all monitored files
    python integrity_check.py reset                # Reset all stored hashes
"""

import sys
import os
import hashlib
import json
import datetime
import argparse

# ── Configuration ─────────────────────────────────────────────────────────────
HASH_STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".integrity_store.json")
LOG_FILE   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "integrity_audit.log")

# ANSI color codes for terminal output
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ── Utility Functions ─────────────────────────────────────────────────────────

def compute_hash(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except PermissionError:
        print(f"{RED}[ERROR]{RESET} Permission denied: {filepath}")
        return None
    except FileNotFoundError:
        print(f"{RED}[ERROR]{RESET} File not found: {filepath}")
        return None


def load_store():
    """Load the stored hash database."""
    if not os.path.exists(HASH_STORE):
        return {}
    try:
        with open(HASH_STORE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"{RED}[ERROR]{RESET} Hash store is corrupted. Run 'reset' to reinitialize.")
        return {}


def save_store(store):
    """Save the hash database securely."""
    with open(HASH_STORE, "w") as f:
        json.dump(store, f, indent=2)
    # Set restrictive permissions on the hash store
    os.chmod(HASH_STORE, 0o600)


def write_audit_log(action, filepath, status, details=""):
    """Write an entry to the audit log."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] ACTION={action} | FILE={filepath} | STATUS={status}"
    if details:
        entry += f" | {details}"
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")


def get_log_files(path):
    """Get all log files from a path (file or directory)."""
    files = []
    if os.path.isfile(path):
        files.append(os.path.abspath(path))
    elif os.path.isdir(path):
        for root, _, filenames in os.walk(path):
            for fname in filenames:
                files.append(os.path.abspath(os.path.join(root, fname)))
    else:
        print(f"{RED}[ERROR]{RESET} Path does not exist: {path}")
    return files


def print_banner():
    print(f"""
{BLUE}{BOLD}╔══════════════════════════════════════════════╗
║   File Integrity Monitoring Tool (FIM)       ║
║   Using SHA-256 Cryptographic Hashing        ║
╚══════════════════════════════════════════════╝{RESET}
""")


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_init(path):
    """
    Initialize: compute and store hashes for all files in path.
    """
    print_banner()
    files = get_log_files(path)
    if not files:
        return

    store = load_store()
    new_count = 0
    updated_count = 0

    print(f"{BOLD}[INIT]{RESET} Initializing integrity hashes for: {path}\n")

    for filepath in files:
        file_hash = compute_hash(filepath)
        if file_hash is None:
            continue

        timestamp = datetime.datetime.now().isoformat()

        if filepath in store:
            store[filepath]["hash"]      = file_hash
            store[filepath]["updated"]   = timestamp
            updated_count += 1
            print(f"  {YELLOW}↺ Updated{RESET}  {filepath}")
        else:
            store[filepath] = {
                "hash":        file_hash,
                "initialized": timestamp,
                "updated":     timestamp
            }
            new_count += 1
            print(f"  {GREEN}✔ Stored{RESET}   {filepath}")

        write_audit_log("INIT", filepath, "STORED", f"hash={file_hash[:16]}...")

    save_store(store)
    print(f"\n{GREEN}{BOLD}Hashes stored successfully.{RESET}")
    print(f"  New files:     {new_count}")
    print(f"  Updated files: {updated_count}")
    print(f"  Total tracked: {len(store)}")
    print(f"  Store location: {HASH_STORE}\n")


def cmd_check(path):
    """
    Check: compare current hashes against stored ones and report discrepancies.
    """
    print_banner()
    files = get_log_files(path)
    if not files:
        return

    store = load_store()
    if not store:
        print(f"{YELLOW}[WARNING]{RESET} No hashes stored yet. Run 'init' first.\n")
        return

    print(f"{BOLD}[CHECK]{RESET} Verifying integrity for: {path}\n")

    modified   = []
    unmodified = []
    new_files  = []
    errors     = []

    for filepath in files:
        current_hash = compute_hash(filepath)
        if current_hash is None:
            errors.append(filepath)
            continue

        if filepath not in store:
            new_files.append(filepath)
            print(f"  {YELLOW}[NEW]{RESET}        {filepath}")
            print(f"               Hash: {current_hash[:32]}...")
            write_audit_log("CHECK", filepath, "NEW_FILE", f"hash={current_hash[:16]}...")
            continue

        stored_hash = store[filepath]["hash"]

        if current_hash == stored_hash:
            unmodified.append(filepath)
            print(f"  {GREEN}[UNMODIFIED]{RESET} {filepath}")
            print(f"               Status: {GREEN}Unmodified — Hash matches{RESET}")
            write_audit_log("CHECK", filepath, "UNMODIFIED")
        else:
            modified.append(filepath)
            print(f"  {RED}[MODIFIED]{RESET}   {filepath}")
            print(f"               Status: {RED}TAMPERED — Hash mismatch detected!{RESET}")
            print(f"               Stored:  {stored_hash[:32]}...")
            print(f"               Current: {current_hash[:32]}...")
            write_audit_log("CHECK", filepath, "MODIFIED",
                          f"stored={stored_hash[:16]}... current={current_hash[:16]}...")
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"{BOLD}{'─'*50}")
    print(f"INTEGRITY CHECK SUMMARY")
    print(f"{'─'*50}{RESET}")
    print(f"  {GREEN}✔ Unmodified:{RESET}  {len(unmodified)}")
    print(f"  {RED}✘ Modified:{RESET}    {len(modified)}")
    print(f"  {YELLOW}⚠ New files:{RESET}   {len(new_files)}")
    print(f"  ✗ Errors:      {len(errors)}")
    print(f"  Total checked: {len(files)}")

    if modified:
        print(f"\n{RED}{BOLD}⚠  ALERT: {len(modified)} file(s) show signs of tampering!{RESET}")
        for f in modified:
            print(f"   → {f}")
        print(f"\n   Run 'update <file>' to re-baseline a file if the change was authorized.\n")
    else:
        print(f"\n{GREEN}{BOLD}✔  All files intact. No tampering detected.{RESET}\n")


def cmd_update(path):
    """
    Update: re-compute and store the hash for a specific file.
    Used when authorized changes have been made.
    """
    print_banner()
    files = get_log_files(path)
    if not files:
        return

    store = load_store()
    print(f"{BOLD}[UPDATE]{RESET} Re-baselining hashes for: {path}\n")

    for filepath in files:
        file_hash = compute_hash(filepath)
        if file_hash is None:
            continue

        timestamp = datetime.datetime.now().isoformat()
        store[filepath] = {
            "hash":        file_hash,
            "initialized": store.get(filepath, {}).get("initialized", timestamp),
            "updated":     timestamp
        }

        print(f"  {GREEN}✔ Updated{RESET}  {filepath}")
        print(f"    New hash: {file_hash[:32]}...")
        write_audit_log("UPDATE", filepath, "HASH_UPDATED", f"new_hash={file_hash[:16]}...")

    save_store(store)
    print(f"\n{GREEN}{BOLD}Hash updated successfully.{RESET}\n")


def cmd_list():
    """
    List all monitored files and their stored hash metadata.
    """
    print_banner()
    store = load_store()

    if not store:
        print(f"{YELLOW}[INFO]{RESET} No files currently monitored. Run 'init <path>' first.\n")
        return

    print(f"{BOLD}[LIST]{RESET} Currently monitored files: {len(store)}\n")
    print(f"{'─'*80}")

    for filepath, data in store.items():
        print(f"  {BLUE}File:{RESET}        {filepath}")
        print(f"  Hash:        {data['hash'][:32]}...")
        print(f"  Initialized: {data.get('initialized', 'N/A')}")
        print(f"  Last update: {data.get('updated', 'N/A')}")
        print(f"{'─'*80}")
    print()


def cmd_reset():
    """
    Reset: clear all stored hashes and start fresh.
    """
    print_banner()
    confirm = input(f"{YELLOW}[WARNING]{RESET} This will delete ALL stored hashes. Type 'yes' to confirm: ")
    if confirm.strip().lower() != "yes":
        print("Reset cancelled.\n")
        return

    if os.path.exists(HASH_STORE):
        os.remove(HASH_STORE)
        write_audit_log("RESET", "ALL", "STORE_CLEARED")
        print(f"{GREEN}[RESET]{RESET} All stored hashes cleared successfully.\n")
    else:
        print(f"{YELLOW}[INFO]{RESET} No hash store found — nothing to reset.\n")


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="integrity_check",
        description="File Integrity Monitoring Tool — detects unauthorized log file tampering using SHA-256",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python integrity_check.py init /var/log
  python integrity_check.py init mylog.log
  python integrity_check.py check /var/log
  python integrity_check.py check /var/log/syslog
  python integrity_check.py update /var/log/syslog
  python integrity_check.py list
  python integrity_check.py reset
        """
    )

    subparsers = parser.add_subparsers(dest="command")

    # init
    p_init = subparsers.add_parser("init", help="Initialize and store hashes for files in path")
    p_init.add_argument("path", help="File or directory to initialize")

    # check
    p_check = subparsers.add_parser("check", help="Check file integrity against stored hashes")
    p_check.add_argument("path", help="File or directory to check")

    # update
    p_update = subparsers.add_parser("update", help="Update stored hash for a file (after authorized change)")
    p_update.add_argument("path", help="File or directory to update")

    # list
    subparsers.add_parser("list", help="List all monitored files and their hash metadata")

    # reset
    subparsers.add_parser("reset", help="Reset all stored hashes (re-initialization)")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args.path)
    elif args.command == "check":
        cmd_check(args.path)
    elif args.command == "update":
        cmd_update(args.path)
    elif args.command == "list":
        cmd_list()
    elif args.command == "reset":
        cmd_reset()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
