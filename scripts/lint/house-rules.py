#!/usr/bin/env python3
"""House-rule lint: zero em-dashes, zero emoji in user-facing strings.

CLAUDE.md: "Zero em-dashes and zero emoji in any user-facing string." This
checks the actual product surfaces (app UI, CLI/daemon output, the relay's
client-visible responses, the public site) rather than the whole repo, since
prose docs and code comments in this codebase use em-dashes freely and are not
what the house rule is about.

Method: for each scanned file, strip comments (block and line, per the file's
language) so only string-literal / markup content remains, then search the
survivors for an em-dash or an emoji codepoint. Comment-stripping is a
best-effort regex, not a parser: a "//" inside a string literal (e.g. a URL)
will truncate the rest of that line. That is a acceptable for a lint whose job
is to flag likely violations, not to be a full tokenizer; a false negative
there just means the surrounding tests/review catch it instead.

Usage: python3 scripts/lint/house-rules.py [--verbose]
Exit 0 if clean, 1 if any violation found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# (directory relative to repo root, glob, comment style)
# comment style is one of: "c" (//, /* */), "html" (<!-- -->)
TARGETS = [
    ("apps/phone/app", "**/*.ts", "c"),
    ("apps/phone/app", "**/*.tsx", "c"),
    ("apps/phone/components", "**/*.ts", "c"),
    ("apps/phone/components", "**/*.tsx", "c"),
    ("apps/phone/src", "**/*.ts", "c"),
    ("apps/phone/src", "**/*.tsx", "c"),
    ("apps/mac/Sigil", "**/*.swift", "c"),
    ("crates/latch/src", "**/*.rs", "c"),
    ("crates/proto/src", "**/*.rs", "c"),
    ("crates/relay-client/src", "**/*.rs", "c"),
    ("crates/softphone/src", "**/*.rs", "c"),
    ("relay", "landing.html", "html"),
    ("site", "*.html", "html"),
    ("docs/design", "sigil-design-brief.html", "html"),
]

# Paths (substring match, POSIX-style) that are never product surface: tests,
# fixtures, generated/vendored trees.
EXCLUDE_SUBSTRINGS = [
    "/node_modules/",
    "/Pods/",
    "/target/",
    "/build/",
    "/dist/",
    "/.expo/",
    "/__vectors__/",
    "/test/",
    "/tests/",
]
EXCLUDE_SUFFIXES = (".test.ts", ".test.tsx", ".spec.ts", "_test.rs")

EM_DASH = "—"

# Deliberately excludes the Dingbats block (U+2700-27BF): this codebase uses
# plain check/cross glyphs (U+2713, U+2717) as functional status marks, not
# decorative emoji, and neither has the Unicode Emoji property. The ranges
# below are the actual pictographic/emoji blocks.
EMOJI_PATTERN = re.compile(
    "["
    "\U0001F300-\U0001FAFF"  # pictographs, emoticons, transport, supplemental
    "\U00002600-\U000026FF"  # misc symbols (weather, stars, ...)
    "\U0001F1E6-\U0001F1FF"  # regional indicators (flag halves)
    "\U0000FE0F"  # variation selector-16 (forces emoji presentation)
    "]"
)

BLOCK_COMMENT_C = re.compile(r"/\*.*?\*/", re.DOTALL)
LINE_COMMENT_C = re.compile(r"//[^\n]*")
BLOCK_COMMENT_HTML = re.compile(r"<!--.*?-->", re.DOTALL)


def _blank_preserving_newlines(match: re.Match) -> str:
    return "\n" * match.group(0).count("\n")


def strip_comments(text: str, style: str) -> str:
    if style == "c":
        text = BLOCK_COMMENT_C.sub(_blank_preserving_newlines, text)
        text = LINE_COMMENT_C.sub("", text)
    elif style == "html":
        text = BLOCK_COMMENT_HTML.sub(_blank_preserving_newlines, text)
    return text


def is_excluded(path: Path) -> bool:
    posix = path.as_posix()
    if posix.endswith(EXCLUDE_SUFFIXES):
        return True
    return any(sub in f"/{posix}/" for sub in EXCLUDE_SUBSTRINGS)


def scan_file(path: Path, style: str) -> list[tuple[int, str, str]]:
    violations = []
    try:
        raw = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return violations
    stripped = strip_comments(raw, style)
    for lineno, line in enumerate(stripped.splitlines(), start=1):
        if EM_DASH in line:
            violations.append((lineno, "em-dash", line.strip()))
        emoji_hits = EMOJI_PATTERN.findall(line)
        if emoji_hits:
            violations.append((lineno, f"emoji ({' '.join(emoji_hits)})", line.strip()))
    return violations


def main() -> int:
    verbose = "--verbose" in sys.argv
    total_violations = 0
    files_scanned = 0

    for rel_dir, pattern, style in TARGETS:
        base = REPO_ROOT / rel_dir
        if not base.exists():
            continue
        for path in sorted(base.glob(pattern)):
            if not path.is_file() or is_excluded(path.relative_to(REPO_ROOT)):
                continue
            files_scanned += 1
            for lineno, kind, line in scan_file(path, style):
                total_violations += 1
                rel = path.relative_to(REPO_ROOT)
                print(f"{rel}:{lineno}: {kind}: {line}")

    if verbose:
        print(f"scanned {files_scanned} files", file=sys.stderr)

    if total_violations:
        print(
            f"\nhouse-rules: {total_violations} violation(s) of the "
            "zero-em-dash / zero-emoji rule (CLAUDE.md). Rewrite the string; "
            "an em-dash in a code comment or a prose doc is fine, this only "
            "flags product-surface copy.",
            file=sys.stderr,
        )
        return 1

    print(f"house-rules: clean ({files_scanned} files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
