# tools/

External tools that aren't distributed on PyPI, cloned/downloaded here so the
`PhoneInfoga`, `SpiderFoot`, and `Recon-ng` engines can find and run them. This
directory is not tracked by pip — set it up once per machine.

## PhoneInfoga (`tools/bin/phoneinfoga.exe`)

Prebuilt Go binary from the official GitHub releases (no compiler needed).

```bash
# Get the latest release tag + asset list:
curl -s https://api.github.com/repos/sundowndev/phoneinfoga/releases/latest
# Download the Windows x86_64 asset, verify its sha256 against
# phoneinfoga_checksums.txt from the same release, then:
tar xzf phoneinfoga_Windows_x86_64.tar.gz -C tools/bin/
```

## SpiderFoot (`tools/spiderfoot/`)

```bash
git clone https://github.com/smicallef/spiderfoot.git tools/spiderfoot
cd tools/spiderfoot
# requirements.txt pins lxml<5 and cryptography<4, which have no prebuilt
# wheels for recent Python on Windows and will fail to compile without MSVC
# Build Tools. Install everything except that lxml pin (a modern lxml already
# satisfies the import), then restore modern cryptography/pyOpenSSL/PyPDF2 —
# the old pins otherwise downgrade shared deps and break other installed
# tools (e.g. pyhanko, maigret).
grep -v "^lxml" requirements.txt > /tmp/req.txt
python -m pip install --user -r /tmp/req.txt
python -m pip install --user --upgrade cryptography pyOpenSSL "PyPDF2>=3.0.1,<4.0.0"
```

## Recon-ng (`tools/recon-ng/`)

```bash
git clone https://github.com/lanmaster53/recon-ng.git tools/recon-ng
cd tools/recon-ng
pip install --user -r REQUIREMENTS
```

**Two Windows-only bugs found and handled** (recon-ng v5.1.2, not upstream-fixed
as of 2026-07):

1. `_load_module()` in `recon/core/base.py` parses each module's category with
   a regex assuming `/`-joined paths, but `os.walk()` yields backslash paths on
   Windows, so it crashes with `AttributeError: 'NoneType' object has no
   attribute 'group'`. **Patched directly in this local clone** — one line at
   the top of `_load_module` normalizing `dirpath` to forward slashes. See the
   comment there.
2. `marketplace install <module>` always fails on Windows with
   `FileNotFoundError` — `_write_local_file` computes the directory to create
   by splitting the target path on `os.sep` (backslash), but the module path
   itself is forward-slash-joined, so it never creates the nested
   `modules/recon/<category>/` folder before trying to write into it. **Not
   patched** (more invasive); instead the `ReconNgEngine._ensure_module()`
   method in `osintforge/engines/framework_recon_ng.py` downloads module files
   itself straight from the official `lanmaster53/recon-ng-modules` repo — the
   same source the marketplace installer uses — with correct path handling.

Only two free, no-API-key modules are wired up for live execution:
`recon/domains-hosts/hackertarget` (domain -> hosts, used automatically for
DOMAIN scans) and the ones under `_LINK_MODULES` in the engine are left as
launch-assist (need an API key, or — for `profiler` — are slow and duplicate
what the `WhatsMyName` engine already does more precisely).

## GHunt

Not vendored here — installed via `pip install ghunt`, then run `ghunt login`
once (interactive Google auth). See project chat history / README for the
walkthrough.
