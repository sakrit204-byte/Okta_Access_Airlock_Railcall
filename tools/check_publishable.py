"""Refuse to publish anything that must not leave this machine.

This exists because of a near miss. `railcall market module sign .` signed 24
files, and four of them were under `.secrets/`, including `okta.json` with the
Okta private key in it and `marketplace_publisher.backup.json` with the
publisher signing seed. One `railcall market publish` would have uploaded both
to a public marketplace.

`.gitignore` does not protect you here. The publisher walks the directory with
its own default ignore list, and `.gitignore` is itself on that list, so it is
never read. The only thing that excludes a file is `.moduleignore`, or this
check failing the build first.

Two independent defences, because the first one is a list and lists go stale:

  by path     anything under a directory that holds credentials
  by content  anything that looks like a key or a token, wherever it lives,
              which is what catches a secret in a file nobody thought to ignore

Run it before signing, and let CI run it on every push:

    python tools/check_publishable.py
"""

import hashlib
import fnmatch
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Copied from the station's _MODULE_DEFAULT_IGNORE in railcall_cli.py. If these
# drift apart this check inspects a different set of files than the one that
# actually ships, which would make it worse than useless.
STATION_DEFAULT_IGNORE = (
    "publisher.succession.json", "publisher.attestation.json",
    "__pycache__/", "*.pyc", "*.pyo", "*.pyd",
    ".pytest_cache/", ".mypy_cache/", ".ruff_cache/",
    ".git/", ".gitignore",
    ".env", ".env.*", "*.env",
    ".railcall/", ".railcall_workspace/",
    "node_modules/",
    "*.log", ".DS_Store",
    "module.sig",
)

FORBIDDEN_PATHS = (
    ".secrets/", "secrets/", "*.pem", "*.key", "*.p12", "*.pfx",
    "credentials*.json", "keys.local.json", "live_findings*.json",
)

# Matched against file contents. Every one of these was chosen to fire on a real
# credential and not on the placeholders the docs legitimately carry, which end
# in an ellipsis or an obvious dummy.
CONTENT_SIGNATURES = (
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/]{40,}",
     "a PEM private key with real looking body"),
    (r'"seed_hex"\s*:\s*"[0-9a-f]{32,}"', "a signing key seed"),
    (r'"privateKeyPem"\s*:\s*"[^"]{40,}"', "an embedded private key"),
    (r"\brc_live_[A-Za-z0-9]{16,}", "a live RailCall API key"),
    (r'"d"\s*:\s*"[A-Za-z0-9_-]{40,}"', "the private component of a JWK"),
    (r"\bsk-[A-Za-z0-9]{32,}", "an API secret key"),
)


def matches(rel_path, patterns):
    """Same semantics as the station's _module_path_matches."""
    parts = rel_path.replace("\\", "/").split("/")
    for pat in patterns:
        if pat.endswith("/"):
            if pat[:-1] in parts:
                return True
        elif fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(parts[-1], pat):
            return True
    return False


def read_moduleignore():
    patterns = list(STATION_DEFAULT_IGNORE)
    path = ROOT / ".moduleignore"
    if path.is_file():
        for line in path.read_text(encoding="utf8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def publishable():
    """Every file `railcall market publish` would upload, as the station sees it."""
    patterns = read_moduleignore()
    found = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        rel_dir = os.path.relpath(dirpath, ROOT).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
        dirnames[:] = [
            d for d in dirnames
            if not matches((rel_dir + "/" + d).lstrip("/"), patterns)
        ]
        for name in filenames:
            rel = (rel_dir + "/" + name).lstrip("/")
            if not matches(rel, patterns):
                found.append(rel)
    return sorted(found)


def main():
    files = publishable()
    problems = []

    for rel in files:
        if matches(rel, FORBIDDEN_PATHS):
            problems.append("%s would be published and holds credentials" % rel)

    for rel in files:
        path = ROOT / rel
        try:
            text = path.read_text(encoding="utf8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern, what in CONTENT_SIGNATURES:
            hit = re.search(pattern, text)
            if hit:
                problems.append(
                    "%s contains %s at offset %d" % (rel, what, hit.start())
                )

    print("publishable files:", len(files))
    digest = hashlib.sha256("\n".join(files).encode("utf8")).hexdigest()[:16]
    print("tree fingerprint :", digest)
    print()

    if problems:
        print("REFUSED: this module is not safe to publish")
        for problem in problems:
            print("  *", problem)
        print()
        print("Add the path to .moduleignore, or move the file out of the module")
        print("directory entirely. Do not publish until this passes.")
        return 1

    print("SAFE TO PUBLISH: no credential reaches the signed tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
