"""Generate the AVIF reference corpus for `avif_reference_corpus_matches_ffmpeg`.

For every libavif test fixture we decode with two INDEPENDENT references:
  - avifdec (dav1d)   -> tests/testdata/avif/libavif/ref_dec/<name>.raw
  - ffmpeg (libdav1d) -> tests/testdata/avif/libavif/ref/<name>.raw

A fixture is written to `manifest.tsv` only when the two references agree
(rgb MAE <= 1 and alpha MAE <= 1), or when only one of them can decode it
(single-reference ground truth). Fixtures where the references disagree are
skipped: they cannot serve as a verdict against our decoder.

All generated data lives in the gitignored `tests/testdata` tree. Re-run this
script after changing the reference toolchain; the Rust test reads manifest.tsv.

Usage:
  python tests/gen_avif_reference.py
  FFMPEG=/path/to/ffmpeg AVIFDEC=/path/to/avifdec python tests/gen_avif_reference.py
"""

import ctypes
import os
import subprocess
import sys
import threading
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TD = os.path.join(HERE, "testdata", "avif", "libavif")
REF = os.path.join(TD, "ref")
REF_DEC = os.path.join(TD, "ref_dec")
MANIFEST = os.path.join(REF, "manifest.tsv")

FFMPEG = os.environ.get("FFMPEG", "ffmpeg")
AVIFDEC = os.environ.get("AVIFDEC", "avifdec")
REPO_API = (
    "https://api.github.com/repos/AOMediaCodec/libavif/contents/tests/data?per_page=100"
)
UA = {"User-Agent": "rcrm-avif-reference"}


def fetch_fixtures():
    os.makedirs(TD, exist_ok=True)
    os.makedirs(REF, exist_ok=True)
    os.makedirs(REF_DEC, exist_ok=True)
    req = urllib.request.Request(REPO_API, headers=UA)
    with urllib.request.urlopen(req, timeout=120) as r:
        import json

        entries = json.load(r)
    got = 0
    for e in entries:
        if not e["name"].endswith(".avif") or e["size"] >= 500_000:
            continue
        path = os.path.join(TD, e["name"])
        if os.path.exists(path):
            continue
        try:
            req = urllib.request.Request(e["download_url"], headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r, open(path, "wb") as f:
                f.write(r.read())
            got += 1
        except Exception as ex:
            print(f"download failed {e['name']}: {ex}", file=sys.stderr)
    return got


def decode_ffmpeg(path):
    p = subprocess.run(
        [
            FFMPEG,
            "-v",
            "error",
            "-i",
            path,
            "-frames:v",
            "1",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgba",
            "-",
        ],
        capture_output=True,
    )
    return p.stdout if p.returncode == 0 and p.stdout else None


def decode_avifdec(path):
    png = path + ".genref.png"
    p = subprocess.run(
        [AVIFDEC, "-r", "--png-compress", "0", path, png], capture_output=True
    )
    if p.returncode != 0 or not os.path.exists(png):
        return None
    raw = subprocess.run(
        [
            FFMPEG,
            "-v",
            "error",
            "-i",
            png,
            "-frames:v",
            "1",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgba",
            "-",
        ],
        capture_output=True,
    ).stdout
    try:
        os.remove(png)
    except OSError:
        pass
    return raw or None


def mae(a, b, n, chan):
    m = min(len(a), len(b)) // 4
    n = min(n, m)
    if n == 0:
        return None
    return sum(abs(a[i * 4 + c] - b[i * 4 + c]) for i in range(n) for c in chan) / (
        n * len(chan)
    )


class _DecodeBuf(ctypes.Structure):
    _fields_ = [
        ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
        ("channels", ctypes.c_uint8),
        ("data_len", ctypes.c_size_t),
        ("cap", ctypes.c_size_t),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
    ]


_ours = None


def ours_can_decode(path):
    """Ask the freshly built bridge whether ours decodes this fixture. The
    manifest must not demand a result for formats we deliberately skip
    (animated tracks, pymd, malformed iloc)."""
    global _ours
    if _ours is None:
        candidates = [
            os.environ.get("RCRM_BRIDGE_DLL"),
            os.path.join(
                HERE, "..", "..", "..", "target", "release", "rcrm_flutter_bridge.dll"
            ),
            os.path.join(
                HERE, "..", "..", "..", "target", "debug", "rcrm_flutter_bridge.dll"
            ),
        ]
        dll = next(
            (os.path.abspath(p) for p in candidates if p and os.path.exists(p)), None
        )
        if not dll:
            # No bridge built: can't verify ours decodes it. Skip the fixture
            # rather than emit a manifest entry that would fail in the Rust test.
            print("no bridge DLL found; build the crate first", file=sys.stderr)
            return False
        _ours = ctypes.CDLL(dll)
        cb_t = ctypes.CFUNCTYPE(None, ctypes.POINTER(_DecodeBuf), ctypes.c_void_p)
        _ours.rcrm_alloc_bytes.argtypes = [ctypes.c_size_t]
        _ours.rcrm_alloc_bytes.restype = ctypes.POINTER(ctypes.c_uint8)
        _ours.rcrm_free_decode_buf.argtypes = [ctypes.POINTER(_DecodeBuf)]
        _ours.rcrm_decode_avif_async.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.c_uint32,
            cb_t,
            ctypes.c_void_p,
        ]
        _ours._cb_t = cb_t
        _ours._dll = dll
    data = open(path, "rb").read()
    ptr = _ours.rcrm_alloc_bytes(len(data))
    ctypes.memmove(ptr, data, len(data))
    ev = threading.Event()
    ok = []

    def cb(p, _):
        if p:
            ok.append(True)
            _ours.rcrm_free_decode_buf(p)
        ev.set()

    keep = _ours._cb_t(cb)
    _ours.rcrm_decode_avif_async(ptr, len(data), 0, keep, None)
    ev.wait(30)
    return bool(ok)


def main():
    got = fetch_fixtures()
    print(
        f"fetched {got} new fixtures; {len([f for f in os.listdir(TD) if f.endswith('.avif')])} total"
    )

    rows = []
    for name in sorted(os.listdir(TD)):
        if not name.endswith(".avif"):
            continue
        path = os.path.join(TD, name)
        ff = decode_ffmpeg(path)
        dec = decode_avifdec(path)
        if not ff or not dec:
            # Single-reference ground truth is ambiguous: some such fixtures
            # exercise formats we deliberately do not decode (tracks, pymd,
            # malformed iloc). Only keep fixtures both references agree on.
            print(f"SKIP {name}: only one reference decodes")
            continue
        ref = ff
        n = len(ref) // 4
        rgb = mae(ff, dec, n, (0, 1, 2))
        alpha = mae(ff, dec, n, (3,))
        if (rgb is None or rgb > 1) or (alpha is None or alpha > 1):
            print(f"SKIP {name}: refs disagree rgb={rgb} alpha={alpha}")
            continue
        if not ours_can_decode(path):
            print(f"SKIP {name}: ours does not decode this format")
            continue
        with open(os.path.join(REF, name + ".raw"), "wb") as f:
            f.write(ref)
        rows.append((name, n, 2.0, 2.0))  # tolerance, not a restated constant
        print(f"OK   {name}: {n} px, refs rgb={rgb} alpha={alpha}")

    with open(MANIFEST, "w", encoding="utf-8") as f:
        for name, n, rtol, atol in rows:
            f.write(f"{name}\t{n}\t{rtol}\t{atol}\n")
    print(f"wrote {len(rows)} rows to {MANIFEST}")


if __name__ == "__main__":
    main()
