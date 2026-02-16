#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import mimetypes
import re
from pathlib import Path
from typing import Dict, Tuple


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _guess_mime(p: Path) -> str:
    mt, _ = mimetypes.guess_type(str(p))
    return mt or "application/octet-stream"


def _minify_css(css: str) -> str:
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)          # /* ... */
    css = re.sub(r"\s+", " ", css)                           # collapse ws
    css = re.sub(r"\s*([{}:;,>])\s*", r"\1", css)            # trim around tokens
    css = re.sub(r";}", "}", css)                            # ;}
    return css.strip()


def _minify_js(js: str) -> str:
    # VERY lightweight minifier: strips /* */ and //... (not perfect for all edge cases)
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    js = re.sub(r"(^|[^\:])//.*?$", r"\1", js, flags=re.M)   # keep http://
    js = re.sub(r"\s+", " ", js)
    js = re.sub(r"\s*([{}();,:=<>+\-*/%&|!?])\s*", r"\1", js)
    return js.strip()


def _minify_html(html: str) -> str:
    # Keep content inside <pre>, <textarea> intact would require proper parser;
    # assume your UI doesn't rely on them.
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    html = re.sub(r">\s+<", "><", html)
    html = re.sub(r"\s{2,}", " ", html)
    return html.strip()


def _data_url_for_file(p: Path) -> str:
    raw = p.read_bytes()
    b64 = base64.b64encode(raw).decode("ascii")
    mime = _guess_mime(p)
    return f"data:{mime};base64,{b64}"


def _inline_css_urls(css: str, base_dir: Path) -> str:
    # url(...) -> inline as data:
    # supports: url(foo.png) / url('foo.png') / url("foo.png")
    def repl(m: re.Match) -> str:
        raw = m.group(1).strip().strip('"\'')
        if raw.startswith("data:") or raw.startswith(("http://", "https://")):
            return f"url({raw})"
        # ignore anchors/fragments
        path = (base_dir / raw).resolve()
        if not path.exists() or path.is_dir():
            return f"url({raw})"
        return f"url({_data_url_for_file(path)})"

    return re.sub(r"url\(([^)]+)\)", repl, css, flags=re.I)


def _inline_img_src(html: str, base_dir: Path) -> str:
    # <img ... src="..."> and <link rel="icon" href="..."> etc.
    # Replace any src/href that points to a local file (not http/data) with data URL.
    def repl_attr(m: re.Match) -> str:
        attr = m.group(1)
        quote = m.group(2)
        val = m.group(3).strip()
        if val.startswith("data:") or val.startswith(("http://", "https://")):
            return m.group(0)
        # skip hash-only
        if val.startswith("#"):
            return m.group(0)
        p = (base_dir / val).resolve()
        if not p.exists() or p.is_dir():
            return m.group(0)
        return f'{attr}={quote}{_data_url_for_file(p)}{quote}'

    # src="..." / href='...'
    return re.sub(r'(\bsrc|\bhref)\s*=\s*([\'"])([^\'"]+)\2', repl_attr, html, flags=re.I)


def _inline_link_css(html: str, base_dir: Path) -> Tuple[str, str]:
    # Collect <link rel="stylesheet" href="..."> and replace with <style>...</style>
    styles = []

    def repl(m: re.Match) -> str:
        tag = m.group(0)
        href_m = re.search(r'href\s*=\s*([\'"])([^\'"]+)\1', tag, flags=re.I)
        rel_m = re.search(r'rel\s*=\s*([\'"])([^\'"]+)\1', tag, flags=re.I)
        if not href_m or not rel_m:
            return tag
        rel = rel_m.group(2).lower().strip()
        if rel != "stylesheet":
            return tag
        href = href_m.group(2).strip()
        if href.startswith(("http://", "https://", "data:")):
            return tag

        p = (base_dir / href).resolve()
        if not p.exists() or p.is_dir():
            return tag

        css = _read_text(p)
        css = _inline_css_urls(css, p.parent)
        css = _minify_css(css)
        styles.append(css)
        return ""  # remove original link

    html2 = re.sub(r"<link\b[^>]*>", repl, html, flags=re.I)
    merged = "\n".join(s for s in styles if s)
    return html2, merged


def _inline_script_src(html: str, base_dir: Path) -> Tuple[str, str]:
    # Collect <script src="..."></script> and replace with inline <script>...</script>
    scripts = []

    def repl(m: re.Match) -> str:
        tag = m.group(0)
        src_m = re.search(r'src\s*=\s*([\'"])([^\'"]+)\1', tag, flags=re.I)
        if not src_m:
            return tag
        src = src_m.group(2).strip()
        if src.startswith(("http://", "https://", "data:")):
            return tag

        p = (base_dir / src).resolve()
        if not p.exists() or p.is_dir():
            return tag

        js = _read_text(p)
        js = _minify_js(js)
        scripts.append(js)
        return ""  # remove original external script tag

    html2 = re.sub(r"<script\b[^>]*\bsrc\s*=\s*([\'\"]).*?\1[^>]*>\s*</script>", repl, html, flags=re.I | re.S)

    merged = "\n".join(s for s in scripts if s)
    return html2, merged


def _js_runtime_obfuscate(js: str) -> str:
    # Simple obfuscation: base64 payload + atob + Function(...)
    # (Works in modern browsers. If you dislike this, remove and just inline js.)
    if not js.strip():
        return ""
    payload = base64.b64encode(js.encode("utf-8")).decode("ascii")
    # Avoid easily grepping payload by chunking
    chunks = [payload[i:i + 120] for i in range(0, len(payload), 120)]
    joined = "+".join([f'"{c}"' for c in chunks])
    wrapper = (
        f'(function(){{var b={joined};'
        f'var s=atob(b);'
        f'(new Function(s))();'
        f'}})();'
    )
    return wrapper


def build_single_html(www_dir: Path, out_html: Path, obfuscate_js: bool) -> None:
    index_html = www_dir / "index.html"
    if not index_html.exists():
        raise FileNotFoundError(f"index.html not found: {index_html}")

    html = _read_text(index_html)

    # Inline CSS files
    html, css_merged = _inline_link_css(html, www_dir)

    # Inline JS files
    html, js_merged = _inline_script_src(html, www_dir)

    # Inline image-like refs in remaining html (img src, icon href, etc.)
    html = _inline_img_src(html, www_dir)

    # Minify inline <style> blocks that already exist
    def min_style(m: re.Match) -> str:
        body = m.group(1)
        body = _inline_css_urls(body, www_dir)
        body = _minify_css(body)
        return f"<style>{body}</style>"

    html = re.sub(r"<style[^>]*>(.*?)</style>", min_style, html, flags=re.I | re.S)

    # Minify inline <script> blocks that already exist (non-module)
    def min_script(m: re.Match) -> str:
        attrs = m.group(1) or ""
        body = m.group(2) or ""
        # keep type=module as-is (minifying can break import lines)
        if re.search(r'type\s*=\s*([\'"])module\1', attrs, flags=re.I):
            return f"<script{attrs}>{body}</script>"
        body2 = _minify_js(body)
        if obfuscate_js:
            body2 = _js_runtime_obfuscate(body2)
        return f"<script{attrs}>{body2}</script>"

    html = re.sub(r"<script([^>]*)>(.*?)</script>", min_script, html, flags=re.I | re.S)

    # Inject merged CSS + JS into </head> and </body> if possible
    if css_merged:
        css_tag = f"<style>{css_merged}</style>"
        if re.search(r"</head\s*>", html, flags=re.I):
            html = re.sub(r"</head\s*>", css_tag + "</head>", html, flags=re.I)
        else:
            html = css_tag + html

    if js_merged:
        js_tag_body = _js_runtime_obfuscate(js_merged) if obfuscate_js else js_merged
        js_tag = f"<script>{js_tag_body}</script>"
        if re.search(r"</body\s*>", html, flags=re.I):
            html = re.sub(r"</body\s*>", js_tag + "</body>", html, flags=re.I)
        else:
            html = html + js_tag

    # Final HTML minify (safe-ish)
    html = _minify_html(html)

    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Pack ./www into single obfuscated out/index.html (inline CSS/JS/images)."
    )
    ap.add_argument("--www", type=Path, default=Path("www"), help="Input www dir (default: ./www)")
    ap.add_argument("--out", type=Path, default=Path("out") / "index.html", help="Output HTML (default: ./out/index.html)")
    ap.add_argument("--no-obfuscate", action="store_true", help="Disable JS base64 wrapper obfuscation (still minifies).")
    args = ap.parse_args()

    www_dir = args.www.resolve()
    out_html = args.out.resolve()

    if not www_dir.exists() or not www_dir.is_dir():
        raise FileNotFoundError(f"www dir not found: {www_dir}")

    build_single_html(www_dir, out_html, obfuscate_js=(not args.no_obfuscate))
    print(f"OK: {out_html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
