"""
build_stages.py
----------------
Run this on your own computer (never upload it anywhere public alongside
real passwords). It asks you for each door's password and clue, then
encrypts each clue with a key derived from its own password, and writes
the result straight into index.html.

Neither the password nor the clue for any door ever appears in plain
text in index.html — only random-looking encrypted data. Typing the
right password is literally the only way to unlock the encryption key
that decrypts that door's clue, so there's nothing meaningful to find
by reading the page's source or dev tools.

Usage:
    python3 build_stages.py

It will look for index.html in the same folder as this script by default.

Requires the "cryptography" package. If you don't have it yet:
    pip install cryptography
"""

import json
import os
import re
import sys
from base64 import b64encode
from getpass import getpass
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("This script needs the 'cryptography' package, which isn't installed yet.")
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_HTML_PATH = SCRIPT_DIR / "index.html"
SECRETS_PATH = SCRIPT_DIR / "stages_secret.json"

START_MARKER = "// ===STAGES_START==="
END_MARKER = "// ===STAGES_END==="

# Must match the PBKDF2_ITERATIONS constant in index.html exactly, or
# players' correct passwords will fail to decrypt.
ITERATIONS = 250000


def encrypt_clue(password: str, clue: str) -> dict:
    """Derive an AES-256 key from the password and use it to encrypt the clue.
    Returns base64-encoded salt/iv/ciphertext — no plaintext of either
    the password or the clue is kept."""
    salt = os.urandom(16)
    iv = os.urandom(12)  # 96-bit nonce, standard for AES-GCM
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    key = kdf.derive(password.strip().lower().encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(iv, clue.encode("utf-8"), None)
    return {
        "salt": b64encode(salt).decode("ascii"),
        "iv": b64encode(iv).decode("ascii"),
        "ciphertext": b64encode(ciphertext).decode("ascii")
    }


def prompt_stages_interactively():
    stages = []
    print("Enter each door in order. Leave the password blank when you're done adding doors.\n")
    i = 1
    while True:
        password = getpass(f"Door {i} password (hidden as you type, blank to finish): ").strip()
        if password == "":
            break
        hint = input(f"Door {i} hint (shown to players to guide them to find the password): ").strip()
        clue = input(f"Door {i} clue (shown to players after they get it right): ").strip()
        stages.append({"password": password, "clue": clue, "hint": hint})
        i += 1
    return stages


def load_stages_from_secrets_file():
    with open(SECRETS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list) or not all("password" in s and "clue" in s for s in data):
        raise ValueError(
            f"{SECRETS_PATH.name} must be a JSON list of objects like "
            '{"password": "...", "clue": "..."}'
        )
    return data


def build_stages_block(stages):
    entries = []
    for stage in stages:
        enc = encrypt_clue(stage["password"], stage["clue"])
        entries.append(
            "    {\n"
            f'      salt: "{enc["salt"]}",\n'
            f'      iv: "{enc["iv"]}",\n'
            f'      ciphertext: "{enc["ciphertext"]}",\n'
            f'      hint: "{stage["hint"]}"\n'
            "    }"
        )
    body = ",\n".join(entries)
    return f"{START_MARKER}\n  const STAGES = [\n{body}\n  ];\n  {END_MARKER}"


def update_html(html_path: Path, new_block: str):
    html = html_path.read_text(encoding="utf-8")

    if START_MARKER not in html or END_MARKER not in html:
        print(f"Could not find the {START_MARKER} / {END_MARKER} markers in {html_path}.")
        print("Make sure you're pointing this script at the right index.html.")
        sys.exit(1)

    pattern = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
        re.DOTALL,
    )
    updated = pattern.sub(new_block.replace("\\", "\\\\"), html, count=1)

    backup_path = html_path.with_suffix(".html.bak")
    backup_path.write_text(html, encoding="utf-8")
    html_path.write_text(updated, encoding="utf-8")

    print(f"\nUpdated: {html_path}")
    print(f"Backup of the previous version saved to: {backup_path}")


def main():
    html_path = DEFAULT_HTML_PATH
    if len(sys.argv) > 1:
        html_path = Path(sys.argv[1]).resolve()

    if not html_path.exists():
        print(f"Couldn't find {html_path}.")
        print("Put this script in the same folder as index.html, or pass the path as an argument:")
        print("    python3 build_stages.py /path/to/index.html")
        sys.exit(1)

    if SECRETS_PATH.exists():
        print(f"Found {SECRETS_PATH.name} — using it instead of asking interactively.")
        stages = load_stages_from_secrets_file()
    else:
        stages = prompt_stages_interactively()
        if not stages:
            print("No doors entered, nothing to do.")
            sys.exit(0)

        save = input(
            f"\nSave these passwords + clues to {SECRETS_PATH.name} so you can "
            "re-run this later without retyping them? [y/N]: "
        ).strip().lower()
        if save == "y":
            SECRETS_PATH.write_text(json.dumps(stages, indent=2), encoding="utf-8")
            print(f"Saved to {SECRETS_PATH}. Keep this file local — it holds your real passwords and clues.")

    block = build_stages_block(stages)
    update_html(html_path, block)

    print(f"\nDone. {len(stages)} door(s) written into {html_path.name}.")
    print("Only encrypted data goes into index.html — no plaintext passwords or clues.")
    print("Never commit stages_secret.json to GitHub — that file holds the real, readable versions.")


if __name__ == "__main__":
    main()
