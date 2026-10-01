# WebCrawler

WebCrawler maps a single host and flags URLs and page elements for manual review:

- Paths that look like administration, login, debugging, or back-office pages.
- Query parameters whose names suggest database input.
- Pages with text inputs, rich-text editors, or comment fields that may handle
  user content.

It follows links with `requests`, escalates a JavaScript-rendered page to
Selenium/Chrome when needed, respects `robots.txt`, streams findings to a JSON
report, and can resume an interrupted crawl.

> **Authorized use only.** This tool probes a website. Run it only against
> systems you own or have explicit written permission to test. You are
> responsible for complying with the law and the target's terms of service.
> A finding identifies a URL or input to review. It does not confirm a vulnerability.

---

## Requirements

- Python 3.9+
- The dependencies in `requirements.txt`:

```bash
pip install -r requirements.txt
```

Optional extras (`requirements-optional.txt`):

```bash
pip install -r requirements-optional.txt
```

| Package | Needed for | If missing |
| --- | --- | --- |
| `requests` | all HTTP fetching | required |
| `beautifulsoup4` | HTML parsing | required |
| `psutil` | RAM guard / state offloading | RAM limit silently disabled |
| `selenium` + Chrome | JavaScript-rendered pages | HTTP-only crawl continues |
| `lxml` | faster HTML parsing | falls back to `html.parser` |

## Quick start

```bash
# Interactive: prompts for a URL, delay, RAM limit and output directory
python webcrawler.py

# Non-interactive
python webcrawler.py https://example.com --delay 1.5 --max-pages 200
```

The crawl writes `crawl_<domain>.json` in the output directory (default: the
current directory). That single file is both the report and the resume
checkpoint.

## Command-line reference

| Option | Default | Description |
| --- | --- | --- |
| `url` | *(prompt)* | Base URL to crawl. |
| `-d`, `--delay` | `2.0` | Seconds between requests (politeness delay). |
| `--ram-limit MB` | `400` | Offload state to disk once the Python process RSS exceeds this. |
| `-o`, `--output-dir` | `.` | Directory for the JSON report/state file. |
| `--timeout` | `10.0` | Per-request timeout, in seconds. |
| `--max-pages` | *(none)* | Stop after this many pages. |
| `--max-page-bytes` | `2000000` | Truncate page bodies larger than this. |
| `--checkpoint-every` | `50` | Save state every N pages (`0` disables periodic saves). |
| `--min-static-links` | `3` | Below this link count, a JS-looking page escalates to Selenium. |
| `--no-selenium` | off | Disable the Selenium/Chrome fallback entirely. |
| `--ignore-robots` | off | Do not consult `robots.txt`. |
| `--fresh` | off | Ignore saved state and start over. |
| `--resume` | off | Resume saved state without prompting. |
| `-q`, `--quiet` | off | Suppress per-page progress. |
| `--version` | | Print version and exit. |

## How detection works

Detection patterns live in [`signatures.py`](signatures.py). The crawler in
`webcrawler.py` reads them from that module. Update the patterns there; changes
to how pages are fetched or analyzed belong in the crawler.

- **Admin paths** match `signatures.ADMIN_PATH_REGEXES` against the URL *path*
  with `re.IGNORECASE`, e.g. `/admin`, `/wp-login.php`, `/phpmyadmin/`,
  `/.env`, `/api/v1/admin`.
- **SQL injection candidates** are query-string parameters whose name
  (case-insensitively) is in `signatures.SQLI_PARAM_NAMES`, e.g. `id`, `cat`,
  `order_by`, `template`. A numeric value such as `?id=3` is marked
  `[numeric]` to help identify numeric inputs for review.
- **XSS / input sinks** come from parsing the page: text inputs and
  `textarea`s, `contenteditable` elements, rich-text editors (TinyMCE,
  CKEditor, Quill, …) and comment/review/chat surfaces. Each finding records
  the matched selectors and any POST forms.

The fingerprints are deliberately broad. Expect some false positives; treat the
report as a triage list.

## Output

The report is JSON with four top-level sections:

```json
{
  "meta":   { "base_url": "...", "status": "complete", "pages_visited": 42, "...": "..." },
  "resume": { "visited": ["..."], "stack": ["..."] },
  "all_links": ["https://example.com/", "..."],
  "findings": {
    "admin_pages":     [{ "url": "...", "matched_pattern": "...", "found_at": "..." }],
    "sqli_candidates": [{ "url": "...", "suspicious_params": { "id": { "value": "3", "numeric": true } } }],
    "xss_candidates":  [{ "url": "...", "xss_analysis": { "inputs": [], "rich_editors": [], "comment_sections": [], "post_forms": [] } }]
  }
}
```

A short, human-readable summary is printed when the crawl finishes.

## Resuming, checkpoints and RAM

- State is written to a temporary file and renamed into place. This reduces the
  risk of leaving a partial report when a write is interrupted.
- State is saved every `--checkpoint-every` pages and whenever RAM exceeds
  `--ram-limit`. On save, the in-memory link/finding buffers are cleared and
  merged with what is already on disk. This reduces buffer growth; `--ram-limit`
  is an offload threshold, not a hard cap on process memory.
- If a state file exists, the crawler asks whether to resume (interactive
  shells) or resumes automatically (piped/non-interactive runs). Use `--fresh`
  to force a new crawl or `--resume` to skip the prompt.
- A crawl marked `"status": "complete"` is never resumed; a new crawl starts.

## Selenium fallback

When a fetched page yields fewer than `--min-static-links` links *and* contains
a `<script>`, the crawler re-renders that page with headless Chrome. As soon as
a page again serves real links over plain HTTP, it drops back to `requests`.
If Selenium or Chrome is unavailable, the crawler prints a note and continues
HTTP-only instead of failing.

## Tests

The test suite is offline and needs no network:

```bash
python -m unittest discover -s tests -v
```

It covers URL normalization, admin/SQLi/XSS heuristics, signature invariants
and state save/resume/deduplication.

## Project layout

```
webcrawler.py            crawler, CLI and reporting
signatures.py            detection cheat sheet (all patterns)
tests/test_core.py       offline unit tests
requirements.txt         core dependencies
requirements-optional.txt  Selenium and lxml
```

## Limitations

- **Single host.** Cross-domain links are ignored (`_same_domain` compares the
  hostname case-insensitively; `www.example.com` and `example.com` are treated
  as different hosts).
- **Heuristic, not proof.** Nothing here confirms an exploit; findings are
  candidates for manual review.
- **No POST crawling.** Forms are reported but not submitted.
- **Rate limits and bot protection** can cause partial crawls; the state file
  preserves progress so you can resume later.
- **`robots.txt`** is respected unless you pass `--ignore-robots`.

## License

Released under the [MIT License](LICENSE).
