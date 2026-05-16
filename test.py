!/usr/bin/env python3
import os, json, uuid, sqlite3, subprocess, threading, time, shutil
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

app = Flask(__name__)

BASE_DIR = Path(__file__).parent
DB_PATH  = BASE_DIR / "data" / "scans.db"
RES_DIR  = BASE_DIR / "data" / "results"
RES_DIR.mkdir(parents=True, exist_ok=True)

MODES = {
    "dir_basic":        ("Dir Fuzzing",         "/usr/share/wordlists/dirb/common.txt"),
    "dir_ext":          ("Dir + Extensions",    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
    "ext_only":         ("Extension Fuzzing",   "/usr/share/wordlists/seclists/Discovery/Web-Content/web-extensions.txt"),
    "dir_ext_combined": ("Dir+Ext Combined",    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
    "config_files":     ("Config Discovery",    "/usr/share/wordlists/dirb/common.txt"),
    "subdomains":       ("Subdomains",          "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1mil-5000.txt"),
    "vhosts":           ("VHost Enum",          "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1mil-5000.txt"),
    "get_params":       ("GET Parameters",      "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt"),
    "post_fuzz":        ("POST Fuzzing",        "/usr/share/wordlists/dirb/common.txt"),
    "bruteforce":       ("Brute-Force Auth",    "users.txt"),
}

# scan_id -> list[str]  (live output lines)
live_out  = {}
# scan_id -> Popen
scan_proc = {}
