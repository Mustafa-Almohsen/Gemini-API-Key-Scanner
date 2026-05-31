## Demo

https://github.com/user-attachments/assets/ef09a517-b183-4096-9bbe-a72f3005ebd9




Scans targets for exposed Google API keys, validates them against Gemini APIs, bypasses referrer restrictions, and demonstrates real impact by uploading data to prove access.

---

## Features

- Multi-target scanning - Single URL, domain list, JS file, or JS URL list
- Deep crawling - Configurable depth to discover JS files
- Smart regex** - Extracts `AIza...` keys from JavaScript
- Automatic validation - Tests each key against Gemini `generateContent`
- Referer bypass** - Auto-retries with `Referer: https://www.google.com/` on 403
- Impact demonstration - Uploads corpus + document to prove write access
- Max corpora handling - Auto-deletes old corpora if limit (10) is hit
- Capability testing - Tests text/image/TTS/video generation, saves evidence
- Threaded - Fast concurrent scanning

---

## Installation

git clone https://github.com/Mustafa-Almohsen/Gemini-API-Key-Scanner  

cd Gemini-API-Key-Scanner  

pip install requests

---

## Usage

### Interactive Menu

python3 gemini_keyhunt.py


### CLI Flags (for VPS / automation)

| Flag | Description |
|------|-------------|
| `--target URL` | Scan a single domain/URL |
| `--targets FILE` | Scan multiple targets from file |
| `--js-file URL` | Scan a single JS file URL |
| `--js-list FILE` | Scan multiple JS URLs from file |
| `--validate-key KEY` | Validate a single API key |
| `--validate-list FILE` | Validate keys from file |
| `--capability KEY` | Full capability test on a key |
| `--yes` | Assume yes to prompts (non-interactive / cron) |
| `--depth N` | Crawl depth (default: 2) |
| `--threads N` | Concurrent threads (default: 10) |
| `--output FILE` | Output file for results |
| `--no-color` | Disable colored output |

### Examples

# Scan a single target with depth 3
python3 gemini_keyhunt.py --target https://example.com --depth 3

# Scan list of targets
python3 gemini_keyhunt.py --targets targets.txt --threads 20

# Scan JS files directly
python3 gemini_keyhunt.py --js-list jsurls.txt

# Validate a found key
python3 gemini_keyhunt.py --validate-key AIzaSyXXXXXXXXXXXXXXXXXXXXX

# Full capability test
python3 gemini_keyhunt.py --capability AIzaSyXXXXXXXXXXXXXXXXXXXXX

---

## Key Status Meanings

| Status | Meaning |
|--------|---------|
| `VULNERABLE` | Key works - Gemini API accessible |
| `403 BYPASSED` | Referer restriction bypassed |
| `LEAKED` | Key flagged by Google - move on |
| `INVALID` | Key doesn't work |

---

## Impact Demonstration

When a key is vulnerable, the tool:
1. Creates a corpus via Generative Language API
2. Uploads a document with test data
3. Verifies retrieval of uploaded content
4. Cleans up (deletes test corpus)

This proves real write access - not just read.

---

## Output

- `results.txt` - Found keys with source URLs
- `vulnerable_keys.txt` - Confirmed vulnerable keys
- `gemini_evidence/` - Capability test evidence (audio, etc.)

---

## Author

**Mustafa** - [YouTube](https://www.youtube.com/@Try.smarter) | [Linkdelin](https://www.linkedin.com/in/mustafa-almohsen-054335276/)

---

## Disclaimer

For authorized security testing only. Do not use against targets without permission.
