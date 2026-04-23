#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import base64
import gzip
import mimetypes
import re
import shutil
from pathlib import Path
from typing import Tuple

try:
    import minify_html
except ImportError:
    minify_html = None

try:
    import brotli
except ImportError:
    brotli = None


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _guess_mime(p: Path) -> str:
    mt, _ = mimetypes.guess_type(str(p))
    return mt or "application/octet-stream"


def _minify_css(css: str) -> str:
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    css = re.sub(r"\s+", " ", css)
    css = re.sub(r"\s*([{}:;,>])\s*", r"\1", css)
    css = re.sub(r";}", "}", css)
    return css.strip()


def _minify_js(js: str) -> str:
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    js = re.sub(r"(;|=|,|\(|\[|\{|^)\s*//.*?$", r"\1", js, flags=re.M)
    js = re.sub(r"\s+", " ", js)
    js = re.sub(r"\s*([{}();,:=<>+\-*%&|!?])\s*", r"\1", js)
    return js.strip()


def _data_url_for_file(p: Path) -> str:
    raw = p.read_bytes()
    b64 = base64.b64encode(raw).decode("ascii")
    mime = _guess_mime(p)
    return f"data:{mime};base64,{b64}"


def _inline_css_urls(css: str, base_dir: Path) -> str:
    def repl(m: re.Match) -> str:
        raw = m.group(1).strip().strip('"\'')
        if raw.startswith("data:") or raw.startswith(("http://", "https://")):
            return f"url({raw})"
        path = (base_dir / raw).resolve()
        if not path.exists() or path.is_dir():
            return f"url({raw})"
        return f"url({_data_url_for_file(path)})"

    return re.sub(r"url\(([^)]+)\)", repl, css, flags=re.I)


def _inline_img_src(html: str, base_dir: Path) -> str:
    def repl_attr(m: re.Match) -> str:
        attr = m.group(1)
        quote = m.group(2)
        val = m.group(3).strip()
        if val.startswith("data:") or val.startswith(("http://", "https://")):
            return m.group(0)
        if val.startswith("#"):
            return m.group(0)
        p = (base_dir / val).resolve()
        if not p.exists() or p.is_dir():
            return m.group(0)
        return f'{attr}={quote}{_data_url_for_file(p)}{quote}'

    return re.sub(r'(\bsrc|\bhref)\s*=\s*([\'"])([^\'"]+)\2', repl_attr, html, flags=re.I)


def _inline_link_css(html: str, base_dir: Path) -> Tuple[str, str]:
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
        return ""

    html2 = re.sub(r"<link\b[^>]*>", repl, html, flags=re.I)
    merged = "\n".join(s for s in styles if s)
    return html2, merged


def _inline_script_src(html: str, base_dir: Path) -> Tuple[str, str]:
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
        return ""

    html2 = re.sub(r"<script\b[^>]*\bsrc\s*=\s*([\'\"]).*?\1[^>]*>\s*</script>", repl, html, flags=re.I | re.S)

    merged = "\n".join(s for s in scripts if s)
    return html2, merged




def copy_favicon(www_dir: Path, out_dir: Path) -> None:
    favicon_src = www_dir / "favicon.ico"
    if favicon_src.exists():
        out_dir.mkdir(parents=True, exist_ok=True)
        favicon_dst = out_dir / "favicon.ico"
        shutil.copyfile(favicon_src, favicon_dst)


def build_single_html(www_dir: Path, out_html: Path) -> None:
    index_html = www_dir / "index.html"
    if not index_html.exists():
        raise FileNotFoundError(f"index.html not found: {index_html}")

    html = _read_text(index_html)

    html, css_merged = _inline_link_css(html, www_dir)
    html, js_merged = _inline_script_src(html, www_dir)
    html = _inline_img_src(html, www_dir)

    def min_style(m: re.Match) -> str:
        body = m.group(1)
        body = _inline_css_urls(body, www_dir)
        body = _minify_css(body)
        return f"<style>{body}</style>"

    html = re.sub(r"<style[^>]*>(.*?)</style>", min_style, html, flags=re.I | re.S)

    def min_script(m: re.Match) -> str:
        attrs = m.group(1) or ""
        body = m.group(2) or ""
        if re.search(r'type\s*=\s*([\'"])module\1', attrs, flags=re.I):
            return f"<script{attrs}>{body}</script>"
        body2 = _minify_js(body)
        return f"<script{attrs}>{body2}</script>"

    html = re.sub(r"<script([^>]*)>(.*?)</script>", min_script, html, flags=re.I | re.S)

    if css_merged:
        css_tag = f"<style>{css_merged}</style>"
        if re.search(r"</head\s*>", html, flags=re.I):
            html = re.sub(r"</head\s*>", lambda m: css_tag + "</head>", html, flags=re.I)
        else:
            html = css_tag + html

    if js_merged:
        js_tag = f"<script>{js_merged}</script>"
        if re.search(r"</body\s*>", html, flags=re.I):
            html = re.sub(r"</body\s*>", lambda m: js_tag + "</body>", html, flags=re.I)
        else:
            html = html + js_tag

    if minify_html:
        html = minify_html.minify(
            html,
            minify_js=True,
            minify_css=True,
            remove_processing_instructions=True,
            keep_spaces_between_attributes=False,
            remove_empty_attributes=True,
            keep_comments=False,
            keep_ssi_directives=False,
        )
    else:
        html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
        html = re.sub(r">\s+<", "><", html)
        html = re.sub(r"\s{2,}", " ", html)
        html = html.strip()

    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html + "\n", encoding="utf-8")


def build_gzip_html(in_html: Path, out_gz: Path) -> None:
    data = in_html.read_bytes()
    with gzip.open(out_gz, 'wb', compresslevel=9) as f:
        f.write(data)


def build_brotli_html(in_html: Path, out_br: Path) -> None:
    data = in_html.read_bytes()
    compressed = brotli.compress(data, quality=11, lgwin=24)
    out_br.write_bytes(compressed)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Pack ./www into single obfuscated out/index.html (inline CSS/JS/images)."
    )
    ap.add_argument("--www", type=Path, default=Path("www"), help="Input www dir (default: ./www)")
    ap.add_argument("--out", type=Path, default=Path("out") / "index.html", help="Output HTML (default: ./out/index.html)")
    ap.add_argument("--gzip", action="store_true", help="Also create gzip-compressed version (.html.gz)")
    ap.add_argument("--gzip-only", action="store_true", help="Only output gzip version, delete uncompressed HTML")
    ap.add_argument("--brotli", action="store_true", help="Also create Brotli-compressed version (.html.br)")
    ap.add_argument("--brotli-only", action="store_true", help="Only output Brotli version, delete uncompressed HTML")
    args = ap.parse_args()

    www_dir = args.www.resolve()
    out_html = args.out.resolve()

    if not www_dir.exists() or not www_dir.is_dir():
        raise FileNotFoundError(f"www dir not found: {www_dir}")

    build_single_html(www_dir, out_html)
    copy_favicon(www_dir, out_html.parent)

    original_size = out_html.stat().st_size
    print(f"OK: {out_html} ({original_size} bytes)")

    if args.gzip or args.gzip_only:
        gz_path = out_html.with_suffix('.html.gz')
        build_gzip_html(out_html, gz_path)
        gz_size = gz_path.stat().st_size
        compression_ratio = (1 - gz_size / original_size) * 100
        print(f"Gzip: {gz_path} ({gz_size} bytes, {compression_ratio:.1f}% smaller)")

        if args.gzip_only:
            out_html.unlink()
            print(f"Removed: {out_html}")

    if args.brotli or args.brotli_only:
        if not brotli:
            print("ERROR: brotli module not installed")
            return 1
        br_path = out_html.with_suffix('.html.br')
        build_brotli_html(out_html, br_path)
        br_size = br_path.stat().st_size
        compression_ratio = (1 - br_size / original_size) * 100
        print(f"Brotli: {br_path} ({br_size} bytes, {compression_ratio:.1f}% smaller)")

        if args.brotli_only:
            out_html.unlink()
            print(f"Removed: {out_html}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
