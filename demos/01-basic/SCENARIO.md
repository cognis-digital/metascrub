# Demo 01 - Clean a release asset before publishing

You're about to publish `release_banner.png` to the company website. Before it
goes out you want to make sure it isn't leaking who made it, on what machine, or
when. METASCRUB scans the PNG container and strips the ancillary metadata
chunks while leaving the actual image bytes (IHDR/IDAT/IEND) untouched.

## Build the demo input

The demo input is a tiny but valid PNG carrying three realistic leaks. Generate
it (stdlib only, no install):

```
python demos/01-basic/make_demo.py
```

This writes `demos/01-basic/release_banner.png` with:

- a `tEXt` chunk: `Author = Jane Doe <jane@acme.example>`
- a `tEXt` chunk: `Software = Adobe Photoshop 25.0 (Macintosh)`
- a `tIME` chunk: last-modified `2026-06-08 14:03:09`

## 1. Scan (read-only) - see what would leak

```
python -m metascrub scan demos/01-basic/release_banner.png
```

Expected: three findings (png:tEXt, png:tEXt, png:tIME) and a **non-zero exit
code (1)**, so this can gate a CI release step.

## 2. JSON output for tooling

```
python -m metascrub --format json scan demos/01-basic/release_banner.png
```

## 3. Clean - write a sanitized copy

```
python -m metascrub clean demos/01-basic/release_banner.png -o banner_clean.png
```

Re-scanning the cleaned file reports **no identifying metadata** and exits 0.
The IHDR/IDAT/IEND image data is preserved byte-for-byte, so the picture still
renders identically.

> METASCRUB is a defensive sanitization tool. Run it only on files you own or
> are authorized to release.
