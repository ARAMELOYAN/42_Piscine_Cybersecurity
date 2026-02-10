#!/usr/bin/env python3
import argparse
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

try:
    import piexif  # type: ignore
except Exception:
    piexif = None


IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".gif", ".bmp")


# ------------------------ helpers ------------------------

def fmt_bytes(n: int) -> str:
    v = float(n)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if v < 1024.0 or u == "TB":
            return f"{int(v)} {u}" if u == "B" else f"{v:.1f} {u}"
        v /= 1024.0
    return f"{v:.1f} TB"


def file_times(path: str) -> Tuple[Optional[str], Optional[str]]:
    """mtime and ctime (Linux: ctime is metadata change time, not true creation time)."""
    try:
        st = os.stat(path)
    except OSError:
        return None, None
    mtime = datetime.fromtimestamp(st.st_mtime).isoformat(sep=" ", timespec="seconds")
    ctime = datetime.fromtimestamp(st.st_ctime).isoformat(sep=" ", timespec="seconds")
    return mtime, ctime


def decode_gps(gps_ifd: Dict[int, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in gps_ifd.items():
        out[GPSTAGS.get(k, k)] = v
    return out


def get_exif_pillow(path: str) -> Dict[str, Any]:
    """Best-effort EXIF read using Pillow."""
    try:
        with Image.open(path) as im:
            exif = im.getexif()
            if not exif:
                return {}
            out: Dict[str, Any] = {}
            for tag_id, value in exif.items():
                tag_name = TAGS.get(tag_id, tag_id)
                if tag_name == "GPSInfo" and isinstance(value, dict):
                    out["GPSInfo"] = decode_gps(value)
                else:
                    out[str(tag_name)] = value
            return out
    except Exception:
        return {}


def pick_creation_date(exif: Dict[str, Any]) -> Optional[str]:
    for key in ("DateTimeOriginal", "DateTimeDigitized", "DateTime"):
        if key in exif:
            return str(exif[key])
    return None


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def out_path_for(src: str, out_dir: Optional[str], suffix: str = "") -> str:
    base = os.path.basename(src)
    root, ext = os.path.splitext(base)
    ext = ext or ""
    if suffix:
        base = f"{root}{suffix}{ext}"
    if out_dir:
        ensure_dir(out_dir)
        return os.path.join(out_dir, base)
    return os.path.join(os.path.dirname(src) or ".", base)


def is_jpeg(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in (".jpg", ".jpeg")


# ------------------------ BONUS: strip metadata ------------------------

def strip_metadata(src: str, dst: str) -> None:
    """
    Remove metadata by re-saving without passing EXIF/PNG info.
    Works for many formats. For JPEG we preserve quality as best effort.
    """
    with Image.open(src) as im:
        # Copy pixel data to detach from original file object
        im_copy = im.copy()

        save_kwargs = {}
        if im.format == "JPEG" or is_jpeg(src):
            # Avoid quality drop
            save_kwargs["quality"] = 95
            save_kwargs["optimize"] = True
            save_kwargs["progressive"] = True

        # Critical: do NOT pass exif=... and do NOT pass pnginfo=...
        im_copy.save(dst, **save_kwargs)


# ------------------------ BONUS: set metadata ------------------------

# Friendly keys -> EXIF tag IDs (common, minimal)
# NOTE: These are classic EXIF tags (0th IFD usually)
EXIF_SET_MAP = {
    "Artist": 315,
    "Copyright": 33432,
    "Software": 305,
    "ImageDescription": 270,
    "Make": 271,
    "Model": 272,
}

def set_metadata_jpeg(src: str, dst: str, kvs: List[Tuple[str, str]]) -> None:
    """
    Set metadata for JPEG.
    If piexif exists: robust write.
    Else: limited Pillow write for a few tags.
    """
    if not is_jpeg(src):
        raise ValueError("--set currently supported reliably only for JPEG/JPG")

    if piexif is not None:
        # Robust path
        exif_dict = piexif.load(src)

        for k, v in kvs:
            if k in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
                # These live in different IFDs
                if k == "DateTime":
                    exif_dict["0th"][piexif.ImageIFD.DateTime] = v.encode("utf-8")
                elif k == "DateTimeOriginal":
                    exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal] = v.encode("utf-8")
                elif k == "DateTimeDigitized":
                    exif_dict["Exif"][piexif.ExifIFD.DateTimeDigitized] = v.encode("utf-8")
                continue

            if k in EXIF_SET_MAP:
                tag_id = EXIF_SET_MAP[k]
                # 0th IFD is the most common place for these tags
                exif_dict["0th"][tag_id] = v.encode("utf-8")
            else:
                raise ValueError(f"Unsupported key for --set: {k}. Supported: {sorted(list(EXIF_SET_MAP.keys()) + ['DateTime','DateTimeOriginal','DateTimeDigitized'])}")

        exif_bytes = piexif.dump(exif_dict)
        with Image.open(src) as im:
            im.save(dst, exif=exif_bytes, quality=95, optimize=True, progressive=True)
        return

    # Fallback: limited Pillow path
    with Image.open(src) as im:
        exif = im.getexif()
        for k, v in kvs:
            if k in EXIF_SET_MAP:
                exif[EXIF_SET_MAP[k]] = v
            else:
                raise ValueError(
                    f"Unsupported key without piexif: {k}. "
                    f"Install piexif for more reliable editing."
                )
        im.save(dst, exif=exif, quality=95, optimize=True, progressive=True)


# ------------------------ reporting ------------------------

def print_report(path: str) -> int:
    if not os.path.exists(path):
        print(f"=== {path}\n  !! file not found\n", file=sys.stderr)
        return 1

    size = None
    try:
        size = os.path.getsize(path)
    except OSError:
        pass

    mtime, ctime = file_times(path)
    exif = get_exif_pillow(path)
    exif_dt = pick_creation_date(exif)

    print(f"=== {path}")
    if size is not None:
        print(f"- Size: {fmt_bytes(size)}")
    if mtime:
        print(f"- Modified (mtime): {mtime}")
    if ctime:
        print(f"- Metadata change/creation-ish (ctime): {ctime}")

    try:
        with Image.open(path) as im:
            print(f"- Format: {im.format}")
            print(f"- Mode: {im.mode}")
            print(f"- Dimensions: {im.width} x {im.height}")
    except Exception as e:
        print(f"- Image open failed: {e}")

    print(f"- EXIF date: {exif_dt if exif_dt else '(not found)'}")

    print("\n[EXIF]")
    if not exif:
        print("(no EXIF / metadata found)\n")
        return 0

    keys = sorted([k for k in exif.keys() if k != "GPSInfo"])
    for k in keys:
        print(f"{k}: {exif[k]}")

    if "GPSInfo" in exif:
        print("GPSInfo:")
        gps = exif["GPSInfo"]
        if isinstance(gps, dict):
            for gk in sorted(gps.keys(), key=str):
                print(f"  {gk}: {gps[gk]}")
        else:
            print(f"  {gps}")

    print()
    return 0


# ------------------------ CLI ------------------------

def parse_set_pairs(pairs: List[str]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for s in pairs:
        if "=" not in s:
            raise ValueError(f"Invalid --set value: {s}. Expected KEY=VALUE")
        k, v = s.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            raise ValueError(f"Invalid --set value: {s}. Empty KEY")
        out.append((k, v))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Arachnida Scorpion: display / strip / set image metadata")
    ap.add_argument("files", nargs="+", help="Image files")
    ap.add_argument("--strip", action="store_true", help="Remove metadata and write cleaned copy")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE",
                    help="Set metadata (reliable for JPEG). Can be repeated.")
    ap.add_argument("--out", default=None, help="Output directory for --strip/--set")
    ap.add_argument("--inplace", action="store_true", help="Overwrite input files (dangerous)")
    args = ap.parse_args()

    set_pairs = parse_set_pairs(args.set)

    rc = 0
    for src in args.files:
        # Validate extension minimal (subject wants same extensions as spider)
        ext = os.path.splitext(src)[1].lower()
        if ext and ext not in IMAGE_EXTS:
            print(f"== {src}\n  !! unsupported extension: {ext}\n", file=sys.stderr)
            rc |= 1
            continue

        # If no bonus ops -> just report
        if not args.strip and not set_pairs:
            rc |= print_report(src)
            continue

        # Decide destination
        if args.inplace:
            dst = src
        else:
            # create distinct output filename so we never destroy original by default
            suffix = "_clean" if args.strip and not set_pairs else "_edited"
            dst = out_path_for(src, args.out, suffix=suffix)

        try:
            if args.strip and set_pairs:
                # Strip then set: do in two steps
                tmp = dst + ".tmp"
                strip_metadata(src, tmp)
                set_metadata_jpeg(tmp if is_jpeg(tmp) else src, dst, set_pairs)
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            elif args.strip:
                strip_metadata(src, dst)
            elif set_pairs:
                set_metadata_jpeg(src, dst, set_pairs)

            print(f"[OK] wrote: {dst}", file=sys.stderr)

        except Exception as e:
            print(f"[FAIL] {src}: {e}", file=sys.stderr)
            rc |= 1

    return rc


if __name__ == "__main__":
    raise SystemExit(main())

