#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import CurlFetcher
import argparse
import os
import re
import sys
import time
import hashlib
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque

from bs4 import BeautifulSoup

# Optional backends
try:
    import pycurl  # apt: python3-pycurl
    import io
    HAS_PYCURL = True
except Exception:
    HAS_PYCURL = False

try:
    import requests
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False


ALLOWED_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp"}
DEFAULT_DEPTH = 5
DEFAULT_OUTDIR = "./data"
DEFAULT_DELAY = 0.6
DEFAULT_TIMEOUT = 25

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 ArachnidaSpider/1.0"
)

BASE_HEADERS = [
    f"User-Agent: {UA}",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.9,hy;q=0.8,ru;q=0.7",
    "Connection: keep-alive",
    "Upgrade-Insecure-Requests: 1",
]


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def normalize_url(base: str, link: str) -> str | None:
    if not link:
        return None
    link = link.strip()
    if link.startswith(("javascript:", "mailto:", "tel:")):
        return None
    u = urljoin(base, link)
    u, _ = urldefrag(u)
    return u


def same_host(a: str, b: str) -> bool:
    try:
        return urlparse(a).netloc.lower() == urlparse(b).netloc.lower()
    except Exception:
        return False


def safe_filename(name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", name).strip("._")
    return name or "file"


def content_hash(data: bytes) -> str:
    # Faster than sha256 and more than enough for dedup
    return hashlib.blake2b(data, digest_size=8).hexdigest()

def guess_ext(url: str, content_type: str | None) -> str | None:
    ct = (content_type or "").lower()
    if "image/jpeg" in ct:
        return ".jpg"
    if "image/png" in ct:
        return ".png"
    if "image/gif" in ct:
        return ".gif"
    if "image/bmp" in ct:
        return ".bmp"

    path = urlparse(url).path.lower()
    for ext in ALLOWED_EXTS:
        if path.endswith(ext):
            return ext
    return None


def extract_from_srcset(base_url: str, srcset: str) -> set[str]:
    urls = set()
    for part in [p.strip() for p in srcset.split(",") if p.strip()]:
        token = part.split()[0].strip()
        u = normalize_url(base_url, token)
        if u:
            urls.add(u)
    return urls


def extract_image_urls(base_url: str, html: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    found: set[str] = set()

    for img in soup.find_all("img"):
        for attr in ("src", "data-src", "data-original", "data-lazy-src", "data-zoom-image"):
            v = img.get(attr)
            u = normalize_url(base_url, v) if v else None
            if u:
                found.add(u)

        srcset = img.get("srcset")
        if srcset:
            found |= extract_from_srcset(base_url, srcset)

    for a in soup.find_all("a"):
        href = a.get("href")
        u = normalize_url(base_url, href) if href else None
        if u:
            found.add(u)

    # regex: URLs inside scripts/JSON blobs
    rx = re.compile(
        r"https?://[^\s\"'<>\\]+?\.(?:png|jpe?g|gif|bmp)(?:\?[^\s\"'<>\\]*)?",
        re.IGNORECASE,
    )
    for m in rx.findall(html):
        found.add(m)

    # filter by extension in path
    out = set()
    for u in found:
        path = urlparse(u).path.lower()
        if any(path.endswith(ext) for ext in ALLOWED_EXTS):
            out.add(u)
    return out


def extract_page_links(base_url: str, html: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    links: set[str] = set()

    for a in soup.find_all("a"):
        href = a.get("href")
        u = normalize_url(base_url, href) if href else None
        if u:
            links.add(u)

    for link in soup.find_all("link"):
        rel = link.get("rel") or []
        if isinstance(rel, str):
            rel = [rel]
        rel = [r.lower() for r in rel]
        if any(r in ("next", "prev", "canonical") for r in rel):
            href = link.get("href")
            u = normalize_url(base_url, href) if href else None
            if u:
                links.add(u)

    return links


# ------------------- Fetch backends -------------------

def fetch_pycurl(url: str, timeout: int, referer: str | None = None):
    """
    Returns: (status_code:int, headers:dict[str,str], body:bytes)
    """
    buf = io.BytesIO()
    hdr = io.BytesIO()

    c = pycurl.Curl()
    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.FOLLOWLOCATION, 1)
    c.setopt(pycurl.TIMEOUT, timeout)
    c.setopt(pycurl.CONNECTTIMEOUT, min(10, timeout))
    c.setopt(pycurl.WRITEDATA, buf)
    c.setopt(pycurl.HEADERFUNCTION, hdr.write)
    c.setopt(pycurl.HTTPHEADER, BASE_HEADERS + ([f"Referer: {referer}"] if referer else []))

    # Good defaults (similar to curl CLI behavior)
    c.setopt(pycurl.SSL_VERIFYPEER, 1)
    c.setopt(pycurl.SSL_VERIFYHOST, 2)
    c.setopt(pycurl.ACCEPT_ENCODING, "")  # enable gzip/br automatically if supported

    try:
        c.perform()
        code = c.getinfo(pycurl.RESPONSE_CODE)
    except pycurl.error as ex:
        eprint(f"[fetch:pycurl] failed: {url} ({ex})")
        c.close()
        return None, {}, b""
    finally:
        try:
            c.close()
        except Exception:
            pass

    raw_headers = hdr.getvalue().decode("iso-8859-1", errors="ignore")
    headers = {}
    for line in raw_headers.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    return code, headers, buf.getvalue()


def fetch_requests(url: str, timeout: int, referer: str | None = None):
    if not HAS_REQUESTS:
        return None, {}, b""
    h = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,hy;q=0.8,ru;q=0.7",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if referer:
        h["Referer"] = referer
    try:
        r = requests.get(url, headers=h, timeout=timeout, allow_redirects=True)
        return r.status_code, dict(r.headers), r.content
    except requests.RequestException as ex:
        eprint(f"[fetch:requests] failed: {url} ({ex})")
        return None, {}, b""


def fetch(url: str, timeout: int, referer: str | None = None):
    # Prefer pycurl for rawpixel-like sites
    if HAS_PYCURL:
        return fetch_pycurl(url, timeout, referer=referer)
    return fetch_requests(url, timeout, referer=referer)


def download_image(img_url: str, outdir: str, seen_hashes: set[str], timeout: int, referer: str) -> bool:
    code, headers, data = fetch(img_url, timeout, referer=referer)
    if code != 200 or not data:
        eprint(f"[download] status {code}: {img_url}")
        return False

    ext = guess_ext(img_url, headers.get("Content-Type"))
    if not ext:
        # fallback: by URL path
        path = urlparse(img_url).path.lower()
        if not any(path.endswith(x) for x in ALLOWED_EXTS):
            return False
        ext = os.path.splitext(path)[1] or ".img"

    h = content_hash(data)
    if h in seen_hashes:
        return False
    seen_hashes.add(h)

    base = os.path.basename(urlparse(img_url).path) or "image"
    base = safe_filename(base)
    if not base.lower().endswith(ext):
        base = base + ext

    filename = f"{os.path.splitext(base)[0]}_{h}{ext}"
    path = os.path.join(outdir, filename)

    if os.path.exists(path):
        return False

    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as ex:
        eprint(f"[download] cannot write {path} ({ex})")
        return False

    print(f"[ok] {img_url} -> {path}")
    return True


def crawl(start_url: str, recursive: bool, max_depth: int, outdir: str, timeout: int, delay: float) -> int:
    ensure_dir(outdir)

    visited_pages: set[str] = set()
    seen_img_urls: set[str] = set()
    seen_hashes: set[str] = set()
    queue = deque([(start_url, 0)])
    downloaded = 0

    while queue:
        page_url, depth = queue.popleft()
        if recursive and depth > max_depth:
            continue

        if page_url in visited_pages:
            continue
        visited_pages.add(page_url)

        code, _headers, body = fetch(page_url, timeout, referer="https://www.rawpixel.com/")
        if code != 200 or not body:
            eprint(f"[fetch] status {code}: {page_url}")
            continue

        html = body.decode("utf-8", errors="ignore")
        time.sleep(delay)

        imgs = set()

        # Only parse DOM if it actually contains img tags
        if "<img" in html:
            imgs |= extract_image_urls(page_url, html)
        else:
            # fallback: regex-only extraction
            import re
            rx = re.compile(
                r"https?://[^\s\"'<>\\]+?\.(?:png|jpe?g|gif|bmp)(?:\?[^\s\"'<>\\]*)?",
                re.IGNORECASE,
            )
            for m in rx.findall(html):
                imgs.add(m)
        for img_url in imgs:
            if img_url in seen_img_urls:
                continue
            seen_img_urls.add(img_url)
            if download_image(img_url, outdir, seen_hashes, timeout, referer=page_url):
                downloaded += 1
            time.sleep(delay)

        if recursive and depth < max_depth:
            links = extract_page_links(page_url, html)
            for link in links:
                scheme = urlparse(link).scheme.lower()
                if scheme not in ("http", "https"):
                    continue
                # Safe: stay on same host
                if not same_host(start_url, link):
                    continue
                if link not in visited_pages:
                    queue.append((link, depth + 1))

    return downloaded


def main():
    parser = argparse.ArgumentParser(prog="spider")
    parser.add_argument("-r", action="store_true", help="recursively download images from linked pages")
    parser.add_argument("-l", type=int, default=DEFAULT_DEPTH, help="max recursion depth (default: 5)")
    parser.add_argument("-p", type=str, default=DEFAULT_OUTDIR, help="output directory (default: ./data)")
    parser.add_argument("url", type=str, help="start URL")
    args = parser.parse_args()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        eprint("URL must start with http:// or https://")
        sys.exit(1)

    if not HAS_PYCURL:
        eprint("[warn] pycurl not found. For rawpixel-like sites install: sudo apt install python3-pycurl")

    downloaded = crawl(
        start_url=url,
        recursive=args.r,
        max_depth=args.l,
        outdir=args.p,
        timeout=DEFAULT_TIMEOUT,
        delay=DEFAULT_DELAY,
    )

    print(f"\nDone. Downloaded: {downloaded} image(s) into {os.path.abspath(args.p)}")


if __name__ == "__main__":
    main()

