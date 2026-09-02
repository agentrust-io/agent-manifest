#!/usr/bin/env python3
"""Check that local asset references in the built docs site actually resolve.

mkdocs rewrites relative paths in Markdown links, but it does not touch paths
inside raw HTML tags. So an ``<img src="../assets/x.svg">`` written in a page at
``docs/integrations/page.md`` keeps that exact path in the output, and because
the page is published at ``/integrations/page/`` the browser resolves it to
``/integrations/assets/x.svg``, which does not exist. The Markdown link on the
same line resolves correctly, which is what makes the bug easy to miss.

This checks the built site rather than the source, so it catches the mistake at
any nesting depth and for both Markdown and raw HTML.

Usage:
    mkdocs build -d site
    python scripts/check_built_links.py site
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

# Only follow references to concrete files. Page links resolve to directories
# under mkdocs' default use_directory_urls and are checked by mkdocs itself.
ASSET_SUFFIXES = {
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico",
    ".pdf", ".json", ".csv", ".txt", ".css", ".js", ".map",
    ".woff", ".woff2", ".ttf", ".otf", ".zip", ".tar", ".gz",
}

REFERENCE = re.compile(r"""\b(?:src|href)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""")


def is_local_asset(target: str) -> bool:
    if not target or target.startswith(("#", "//", "data:", "mailto:", "tel:")):
        return False
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return False
    return Path(unquote(parsed.path)).suffix.lower() in ASSET_SUFFIXES


def check(site_dir: Path) -> list[str]:
    failures: list[str] = []
    for page in sorted(site_dir.rglob("*.html")):
        html = page.read_text(encoding="utf-8", errors="replace")
        for match in REFERENCE.finditer(html):
            target = next(g for g in match.groups() if g is not None)
            if not is_local_asset(target):
                continue
            path = unquote(urlparse(target).path)
            if path.startswith("/"):
                resolved = site_dir / path.lstrip("/")
            else:
                resolved = page.parent / path
            if not resolved.resolve().is_file():
                failures.append(
                    f"{page.relative_to(site_dir).as_posix()}: {target}"
                )
    return failures


def main() -> int:
    site_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "site")
    if not site_dir.is_dir():
        print(f"Built site not found at {site_dir}. Run mkdocs build first.")
        return 2

    failures = check(site_dir)
    if failures:
        print(f"{len(failures)} asset reference(s) do not resolve in the built site:\n")
        for failure in failures:
            print(f"  {failure}")
        print(
            "\nA path inside a raw HTML tag is used verbatim. It must resolve from "
            "the published URL of the page, not from the source file location."
        )
        return 1

    print("All local asset references resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
