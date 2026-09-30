#!/usr/bin/env python3
"""Heuristic web crawler for reconnaissance of a single site.

The crawler walks every reachable page on one host and records three classes of
finding:

* **admin / hidden URLs** -- paths that look like admin, login, debug or
  back-office surfaces (see ``signatures.ADMIN_PATH_REGEXES``);
* **SQL injection candidates** -- query parameters whose names commonly carry
  database input (see ``signatures.SQLI_PARAM_NAMES``);
* **XSS / input-sink candidates** -- pages with text inputs, rich-text editors
  or comment surfaces that are worth probing for reflected input.

Pages are fetched with :mod:`requests`; when a page looks JavaScript rendered
the crawler escalates to Selenium/Chrome for that page and drops back to plain
HTTP as soon as the site serves real links again. Findings stream to a JSON
state file that doubles as a resume checkpoint.

This is a reconnaissance aid, not an exploitation tool. Only crawl sites you
own or have explicit written permission to test.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Sequence
from urllib.parse import (
    parse_qs,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup

from signatures import (
    ADMIN_PATH_REGEXES,
    COMMENT_SECTION_FINGERPRINTS,
    RICH_EDITOR_FINGERPRINTS,
    SKIP_INPUT_TYPES,
    SQLI_PARAM_NAMES,
    TEXT_INPUT_TYPES,
    TRACKING_PARAMS,
)

try:  # psutil is optional: without it the RAM guard is simply disabled.
    import psutil
except ImportError:  # pragma: no cover - depends on the environment
    psutil = None

__version__ = '2.0.0'

DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0 Safari/537.36'
)

_NUMERIC_RE = re.compile(r'[+-]?\d+(?:\.\d+)?')


def _pick_html_parser() -> str:
    """Return the fastest installed BeautifulSoup parser."""
    if importlib.util.find_spec('lxml') is not None:
        return 'lxml'
    return 'html.parser'


def _compile_fingerprints(fingerprints: Iterable[str]) -> re.Pattern[str] | None:
    """Compile many substrings into one case-insensitive alternation regex.

    Matching a single regex is far cheaper than looping over dozens of
    substrings for every element on a page.
    """
    parts = sorted({re.escape(f) for f in fingerprints if f})
    if not parts:
        return None
    return re.compile('|'.join(parts), re.IGNORECASE)


_HTML_PARSER = _pick_html_parser()
_RICH_EDITOR_RE = _compile_fingerprints(RICH_EDITOR_FINGERPRINTS)
_COMMENT_SECTION_RE = _compile_fingerprints(COMMENT_SECTION_FINGERPRINTS)


def _now() -> str:
    """Local ISO-8601 timestamp including the UTC offset."""
    return datetime.now().astimezone().isoformat(timespec='seconds')


def _is_numeric(value: str) -> bool:
    return _NUMERIC_RE.fullmatch(value.strip()) is not None


@dataclass
class FetchResult:
    """Outcome of fetching and parsing one page."""

    links: list[str] = field(default_factory=list)
    html: str | None = None
    escalate: bool = False


class SeleniumUnavailable(RuntimeError):
    """Raised when the Selenium fallback cannot be used."""


class WebCrawler:
    """Breadth-first crawler for a single host with heuristic analysis."""

    _HEADERS = {'User-Agent': DEFAULT_USER_AGENT}

    def __init__(
        self,
        base_url: str,
        delay: float = 2.0,
        ram_limit_mb: int = 400,
        output_dir: str = '.',
        *,
        timeout: float = 10.0,
        max_pages: int | None = None,
        max_page_bytes: int = 2_000_000,
        checkpoint_every: int = 50,
        ram_offload_interval: int = 10,
        min_static_links: int = 3,
        allow_selenium: bool = True,
        respect_robots: bool = True,
        fresh: bool = False,
        resume: bool | None = None,
        quiet: bool = False,
    ) -> None:
        self.base_url = base_url
        self.delay = max(0.0, float(delay))
        self.ram_limit = max(1, int(ram_limit_mb)) * 1024 * 1024
        self.output_dir = output_dir
        self.timeout = max(1.0, float(timeout))
        self.max_pages = max_pages
        self.max_page_bytes = max(1024, int(max_page_bytes))
        self.checkpoint_every = max(0, int(checkpoint_every))
        self.ram_offload_interval = max(1, int(ram_offload_interval))
        self.min_static_links = max(1, int(min_static_links))
        self.allow_selenium = allow_selenium
        self.respect_robots = respect_robots
        self.fresh = fresh
        self.resume = resume
        self.quiet = quiet

        if not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url
        base_url = WebCrawler._normalize_url(base_url)
        self.base_url = base_url

        parsed = urlparse(base_url)
        self.domain = parsed.netloc
        self.host = (parsed.hostname or '').lower()
        safe_domain = re.sub(r'[^\w.-]', '_', self.domain) or 'site'
        self.state_file = os.path.join(output_dir, f'crawl_{safe_domain}.json')

        self.visited: set[str] = set()
        self.stack: list[str] = []
        self.all_links: list[str] = []
        self.findings: dict[str, list[dict[str, Any]]] = {
            'admin_pages': [],
            'sqli_candidates': [],
            'xss_candidates': [],
        }

        self.use_selenium = False
        self.driver: Any = None
        self._selenium_unavailable = False
        self._robots: RobotFileParser | None = None
        self._processed = 0
        self._since_save = 0
        self._started_at = _now()
        self._proc = psutil.Process() if psutil is not None else None

    # -- lifecycle ---------------------------------------------------------

    def _setup_selenium(self) -> None:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
        except ImportError as exc:
            raise SeleniumUnavailable('selenium is not installed') from exc

        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--blink-settings=imagesEnabled=false')
        options.add_argument(f'user-agent={self._HEADERS["User-Agent"]}')
        options.page_load_strategy = 'eager'
        try:
            self.driver = webdriver.Chrome(options=options)
        except Exception as exc:  # noqa: BLE001 - driver errors vary by platform
            raise SeleniumUnavailable(f'could not start Chrome: {exc}') from exc
        self.driver.set_page_load_timeout(self.timeout)

    def _close_selenium(self) -> None:
        if self.driver is not None:
            try:
                self.driver.quit()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            self.driver = None

    # -- logging / memory --------------------------------------------------

    def _say(self, message: str = '') -> None:
        if not self.quiet:
            print(message)

    def _rss_mb(self) -> float:
        if self._proc is None:
            return 0.0
        return self._proc.memory_info().rss / (1024 * 1024)

    def _ram_exceeded(self) -> bool:
        if self._proc is None:
            return False
        return self._proc.memory_info().rss > self.ram_limit

    # -- URL helpers -------------------------------------------------------

    def _same_domain(self, url: str) -> bool:
        parts = urlparse(url)
        if parts.scheme not in ('http', 'https'):
            return False
        return (parts.hostname or '').lower() == self.host

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Lowercase the host, drop the fragment/tracking params and sort the
        query so the same page has one canonical key."""
        try:
            parts = urlparse(url)
        except ValueError:
            return url
        if parts.scheme not in ('http', 'https'):
            return url
        query = parse_qs(parts.query, keep_blank_values=True)
        kept = {
            key: value
            for key, value in query.items()
            if key.lower() not in TRACKING_PARAMS
        }
        clean_query = urlencode(sorted(kept.items()), doseq=True)
        return urlunparse((
            parts.scheme,
            parts.netloc.lower(),
            parts.path or '/',
            parts.params,
            clean_query,
            '',
        ))

    def _extract_links(self, soup: BeautifulSoup, url: str) -> list[str]:
        links: list[str] = []
        for anchor in soup.find_all('a', href=True):
            href = (anchor.get('href') or '').strip()
            if not href or href.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
                continue
            normalized = self._normalize_url(urljoin(url, href))
            if self._same_domain(normalized):
                links.append(normalized)
        return list(dict.fromkeys(links))

    # -- robots.txt --------------------------------------------------------

    def _load_robots(self) -> None:
        self._robots = None
        if not self.respect_robots:
            return
        parts = urlparse(self.base_url)
        robots_url = urlunparse((parts.scheme, parts.netloc, '/robots.txt', '', '', ''))
        try:
            response = requests.get(
                robots_url, headers=self._HEADERS, timeout=self.timeout
            )
            if response.status_code == 200:
                parser = RobotFileParser()
                parser.set_url(robots_url)
                parser.parse(response.text.splitlines())
                self._robots = parser
        except requests.RequestException:
            self._robots = None

    def _can_fetch(self, url: str) -> bool:
        if self._robots is None:
            return True
        try:
            return self._robots.can_fetch(self._HEADERS['User-Agent'], url)
        except Exception:  # noqa: BLE001 - malformed robots.txt
            return True

    # -- fetching ----------------------------------------------------------

    def _fetch_static(self, url: str) -> FetchResult:
        self._say(f'[static] {url}')
        try:
            with requests.get(
                url, headers=self._HEADERS, timeout=self.timeout, stream=True
            ) as response:
                status = response.status_code
                if status >= 400:
                    self._say(f'  HTTP {status}; skipped')
                    return FetchResult()
                content_type = response.headers.get('Content-Type', '').lower()
                if content_type and not any(
                    token in content_type for token in ('html', 'xml', 'text')
                ):
                    self._say(f'  skipped non-HTML ({content_type.split(";")[0]})')
                    return FetchResult()
                raw = bytearray()
                for chunk in response.iter_content(65536):
                    raw.extend(chunk)
                    if len(raw) >= self.max_page_bytes:
                        del raw[self.max_page_bytes:]
                        break
                encoding = response.encoding or 'utf-8'
        except requests.RequestException as exc:
            self._say(f'  request failed: {exc}')
            return FetchResult(escalate=self.allow_selenium)

        html = bytes(raw).decode(encoding, errors='replace')
        soup = BeautifulSoup(html, _HTML_PARSER)
        links = self._extract_links(soup, url)
        if (
            self.allow_selenium
            and len(links) < self.min_static_links
            and soup.find('script') is not None
        ):
            self._say(f'  only {len(links)} links and page looks JS-driven; trying Selenium')
            return FetchResult(links=links, html=html, escalate=True)
        self._say(f'  {len(links)} links')
        return FetchResult(links=links, html=html)

    def _fetch_selenium(self, url: str) -> FetchResult:
        if self._selenium_unavailable:
            return FetchResult()
        self._say(f'[selenium] {url}')
        try:
            if self.driver is None:
                self._setup_selenium()
            self.driver.get(url)
            time.sleep(0.5)
            html = self.driver.page_source
            hrefs: Sequence[str] = self.driver.execute_script(
                "return Array.from(document.querySelectorAll('a[href]'), a => a.href);"
            ) or []
            links: list[str] = []
            for href in hrefs:
                normalized = self._normalize_url(str(href))
                if self._same_domain(normalized):
                    links.append(normalized)
            links = list(dict.fromkeys(links))
            self._say(f'  {len(links)} links')
            return FetchResult(links=links, html=html)
        except SeleniumUnavailable as exc:
            self._say(f'  Selenium unavailable ({exc}); continuing with HTTP only')
            self._selenium_unavailable = True
            self.use_selenium = False
            self._close_selenium()
            return FetchResult()
        except Exception as exc:  # noqa: BLE001 - WebDriver errors are varied
            self._say(f'  Selenium error: {exc}')
            self._close_selenium()
            return FetchResult()

    def _fetch(self, url: str) -> FetchResult:
        if self.use_selenium and not self._selenium_unavailable:
            result = self._fetch_selenium(url)
            if len(result.links) >= self.min_static_links:
                self._say('  enough links via Selenium; reverting to HTTP')
                self.use_selenium = False
            return result

        result = self._fetch_static(url)
        if result.escalate and not self._selenium_unavailable:
            self.use_selenium = True
            rendered = self._fetch_selenium(url)
            if not self._selenium_unavailable and rendered.html is not None:
                return rendered
            self.use_selenium = False
        return result

    # -- analysis ----------------------------------------------------------

    @staticmethod
    def _match_admin_path(url: str) -> str | None:
        path = urlparse(url).path
        for regex in ADMIN_PATH_REGEXES:
            if regex.search(path):
                return regex.pattern
        return None

    @staticmethod
    def _sqli_params(url: str) -> dict[str, dict[str, Any]]:
        query = urlparse(url).query
        if not query:
            return {}
        found: dict[str, dict[str, Any]] = {}
        for name, values in parse_qs(query, keep_blank_values=True).items():
            if name.lower() in SQLI_PARAM_NAMES:
                value = values[0] if values else ''
                found[name] = {'value': value, 'numeric': _is_numeric(value)}
        return found

    @staticmethod
    def _input_record(element: str, tag: Any) -> dict[str, Any]:
        return {
            'element': element,
            'id': tag.get('id', ''),
            'name': tag.get('name', ''),
            'class': tag.get('class', []) or [],
        }

    @staticmethod
    def _analyse_html(html: str) -> dict[str, Any]:
        soup = BeautifulSoup(html, _HTML_PARSER)

        inputs: list[dict[str, Any]] = []
        for tag in soup.find_all('textarea'):
            record = WebCrawler._input_record('textarea', tag)
            record['text_like'] = True
            inputs.append(record)
        for tag in soup.find_all('input'):
            input_type = (tag.get('type') or 'text').strip().lower()
            if input_type in SKIP_INPUT_TYPES:
                continue
            record = WebCrawler._input_record(f'input[type={input_type}]', tag)
            record['text_like'] = input_type in TEXT_INPUT_TYPES
            inputs.append(record)
        for tag in soup.find_all(attrs={'contenteditable': True}):
            value = str(tag.get('contenteditable', '')).strip().lower()
            if value in ('', 'true'):
                inputs.append({
                    'element': f'{tag.name}[contenteditable]',
                    'id': tag.get('id', ''),
                    'name': tag.get('name', ''),
                    'class': tag.get('class', []) or [],
                    'text_like': True,
                })

        rich_editors: list[dict[str, Any]] = []
        comment_sections: list[dict[str, Any]] = []
        if _RICH_EDITOR_RE is not None or _COMMENT_SECTION_RE is not None:
            for element in soup.find_all(True):
                combined = (
                    (element.get('id') or '') + ' '
                    + ' '.join(element.get('class') or [])
                ).strip().lower()
                if not combined:
                    continue
                if _RICH_EDITOR_RE is not None:
                    match = _RICH_EDITOR_RE.search(combined)
                    if match:
                        rich_editors.append({
                            'editor': match.group(0).lower(),
                            'element': element.name,
                            'id': element.get('id', ''),
                            'class': element.get('class', []) or [],
                        })
                if _COMMENT_SECTION_RE is not None:
                    match = _COMMENT_SECTION_RE.search(combined)
                    if match:
                        comment_sections.append({
                            'pattern': match.group(0).lower(),
                            'element': element.name,
                            'id': element.get('id', ''),
                            'class': element.get('class', []) or [],
                        })

        post_forms: list[dict[str, Any]] = []
        for form in soup.find_all('form'):
            if (form.get('method') or 'get').upper() == 'POST':
                post_forms.append({
                    'action': form.get('action', ''),
                    'enctype': form.get('enctype', ''),
                    'input_count': len(
                        form.find_all(['input', 'textarea', 'select'])
                    ),
                })

        return {
            'inputs': inputs,
            'rich_editors': rich_editors,
            'comment_sections': comment_sections,
            'post_forms': post_forms,
            'total_text_inputs': len(inputs),
        }

    def _analyse(self, url: str, html: str | None) -> None:
        found_at = _now()

        admin_pattern = self._match_admin_path(url)
        if admin_pattern:
            self.findings['admin_pages'].append({
                'url': url,
                'matched_pattern': admin_pattern,
                'found_at': found_at,
            })

        sqli = self._sqli_params(url)
        if sqli:
            self.findings['sqli_candidates'].append({
                'url': url,
                'suspicious_params': sqli,
                'found_at': found_at,
            })

        if html:
            analysis = self._analyse_html(html)
            if (
                analysis['total_text_inputs']
                or analysis['rich_editors']
                or analysis['comment_sections']
            ):
                self.findings['xss_candidates'].append({
                    'url': url,
                    'xss_analysis': analysis,
                    'found_at': found_at,
                })

    # -- state / persistence ----------------------------------------------

    def _merge_with_disk(self) -> tuple[list[str], dict[str, list[dict[str, Any]]]]:
        """Merge in-memory findings with whatever is already on disk."""
        links: list[str] = []
        findings: dict[str, list[dict[str, Any]]] = {key: [] for key in self.findings}

        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as handle:
                    previous = json.load(handle)
            except (OSError, json.JSONDecodeError):
                previous = {}
            if isinstance(previous, dict):
                stored_links = previous.get('all_links')
                if isinstance(stored_links, list):
                    links = [link for link in stored_links if isinstance(link, str)]
                stored_findings = previous.get('findings')
                if isinstance(stored_findings, dict):
                    for key in findings:
                        entries = stored_findings.get(key)
                        if isinstance(entries, list):
                            findings[key] = [e for e in entries if isinstance(e, dict)]

        seen_links = set(links)
        for link in self.all_links:
            if link not in seen_links:
                links.append(link)
                seen_links.add(link)

        for key, entries in self.findings.items():
            seen_urls = {entry.get('url') for entry in findings[key]}
            for entry in entries:
                if entry.get('url') not in seen_urls:
                    findings[key].append(entry)
                    seen_urls.add(entry.get('url'))

        return links, findings

    def save_state(self, final: bool = False) -> bool:
        links, findings = self._merge_with_disk()
        state = {
            'meta': {
                'base_url': self.base_url,
                'domain': self.domain,
                'started_at': self._started_at,
                'saved_at': _now(),
                'pages_visited': len(self.visited),
                'pages_pending': len(self.stack),
                'pages_processed': self._processed,
                'status': 'complete' if final else 'in_progress',
            },
            'resume': {
                'visited': list(self.visited),
                'stack': list(self.stack),
            },
            'all_links': links,
            'findings': findings,
        }

        tmp_path = self.state_file + '.tmp'
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            with open(tmp_path, 'w', encoding='utf-8') as handle:
                json.dump(state, handle, indent=2, ensure_ascii=False)
            os.replace(tmp_path, self.state_file)
        except OSError as exc:
            self._say(f'  could not write state file: {exc}')
            return False

        self._reset_buffers()
        self._since_save = 0
        self._say(f'  state saved -> {self.state_file} (RAM ~{self._rss_mb():.0f} MB)')
        return True

    def load_state(self) -> bool:
        if not os.path.exists(self.state_file):
            return False
        try:
            with open(self.state_file, 'r', encoding='utf-8') as handle:
                state = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            self._say(f'  state file unreadable ({exc}); starting fresh')
            return False

        if not isinstance(state, dict):
            self._say('  state file has an unexpected shape; starting fresh')
            return False

        meta = state.get('meta') or {}
        if meta.get('status') == 'complete':
            self._say('  previous crawl already complete; starting fresh')
            return False

        resume = state.get('resume') or {}
        visited = resume.get('visited')
        stack = resume.get('stack')
        self.visited = {v for v in visited if isinstance(v, str)} if isinstance(visited, list) else set()
        self.stack = [s for s in stack if isinstance(s, str)] if isinstance(stack, list) else []
        stored_links = state.get('all_links')
        self.all_links = [link for link in stored_links if isinstance(link, str)] if isinstance(stored_links, list) else []

        stored_findings = state.get('findings') or {}
        for key in self.findings:
            entries = stored_findings.get(key)
            self.findings[key] = [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []

        self._started_at = meta.get('started_at', self._started_at)
        self._say(
            f'  resumed: {len(self.visited)} visited, '
            f'{len(self.stack)} pending, {len(self.all_links)} links collected'
        )
        return True

    def _reset_buffers(self) -> None:
        self.all_links.clear()
        for entries in self.findings.values():
            entries.clear()

    def _prepare_queue(self) -> None:
        if self.fresh or not os.path.exists(self.state_file):
            self.stack = [self.base_url]
            return

        should_resume = self.resume
        if should_resume is None:
            if sys.stdin.isatty():
                answer = input(
                    f'  Saved crawl found: {self.state_file}\n'
                    '  Resume it? [Y/n]: '
                ).strip().lower()
                should_resume = answer in ('', 'y', 'yes')
            else:
                should_resume = True

        if should_resume and self.load_state():
            return
        self.stack = [self.base_url]
        self._say('  starting fresh')

    def _after_page(self) -> None:
        self._processed += 1
        self._since_save += 1

        due_checkpoint = (
            self.checkpoint_every > 0
            and self._since_save >= self.checkpoint_every
        )
        due_ram = self._ram_exceeded() and self._since_save >= self.ram_offload_interval
        if not (due_checkpoint or due_ram):
            return
        if due_ram and not due_checkpoint:
            self._say(
                f'  RAM {self._rss_mb():.0f} MB over the '
                f'{self.ram_limit // (1024 * 1024)} MB limit; offloading state'
            )
        self.save_state()

    # -- main loop ---------------------------------------------------------

    def crawl(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        if psutil is None:
            self._say('  note: psutil is not installed, RAM limit is disabled')
        self._load_robots()
        self._prepare_queue()

        self._say('\n' + '=' * 66)
        self._say(f'  crawling {self.base_url}')
        self._say('=' * 66)

        completed = False
        try:
            while self.stack:
                if self.max_pages is not None and self._processed >= self.max_pages:
                    self._say(f'  reached max_pages={self.max_pages}; stopping')
                    break

                current = self.stack.pop()
                if current in self.visited:
                    continue
                if not self._can_fetch(current):
                    self.visited.add(current)
                    self._say(f'[robots] disallowed: {current}')
                    continue

                self.visited.add(current)
                self.all_links.append(current)

                result = self._fetch(current)
                self._analyse(current, result.html)

                for link in reversed(result.links):
                    if link not in self.visited:
                        self.stack.append(link)

                if self.stack:
                    time.sleep(self.delay)
                self._after_page()

            completed = True
        except KeyboardInterrupt:
            self._say('\n  interrupted; saving state for resume')
        finally:
            self._close_selenium()
            self.save_state(final=completed)
            self._print_summary()

    # -- reporting ---------------------------------------------------------

    def _print_summary(self) -> None:
        try:
            with open(self.state_file, 'r', encoding='utf-8') as handle:
                saved = json.load(handle)
            all_links = saved.get('all_links', [])
            findings = saved.get('findings', {}) or {}
        except (OSError, json.JSONDecodeError, AttributeError):
            all_links = self.all_links
            findings = self.findings

        admin = findings.get('admin_pages', []) or []
        sqli = findings.get('sqli_candidates', []) or []
        xss = findings.get('xss_candidates', []) or []

        width = 66
        print('\n' + '=' * width)
        print('  CRAWL COMPLETE')
        print('=' * width)
        print(f'  Pages crawled        : {len(all_links)}')
        print(f'  Admin / hidden URLs  : {len(admin)}')
        print(f'  SQLi candidates      : {len(sqli)}')
        print(f'  XSS / input sinks    : {len(xss)}')
        print(f'  Report               : {self.state_file}')

        if admin:
            print('\n-- ADMIN / HIDDEN URLS ' + '-' * (width - 22))
            for entry in admin:
                print(f'  {entry.get("url", "?")}')
                print(f'      matched: {entry.get("matched_pattern", "?")}')

        if sqli:
            print('\n-- SQL INJECTION CANDIDATES ' + '-' * (width - 28))
            for entry in sqli:
                print(f'  {entry.get("url", "?")}')
                for name, info in (entry.get('suspicious_params') or {}).items():
                    if info.get('numeric'):
                        detail = '[numeric]'
                    else:
                        detail = f'= {info.get("value", "")!r}'
                    print(f'      ?{name} {detail}')

        if xss:
            print('\n-- XSS / INPUT-SINK CANDIDATES ' + '-' * (width - 31))
            for entry in xss:
                analysis = entry.get('xss_analysis') or {}
                print(f'  {entry.get("url", "?")}')
                print(
                    f'      text_inputs={analysis.get("total_text_inputs", 0)}  '
                    f'rich_editors={len(analysis.get("rich_editors") or [])}  '
                    f'comment_sections={len(analysis.get("comment_sections") or [])}  '
                    f'post_forms={len(analysis.get("post_forms") or [])}'
                )

        print('\n' + '=' * width + '\n')


# ---------------------------------------------------------------------------
# Command line interface
# ---------------------------------------------------------------------------


def _normalize_base_url(raw: str) -> str:
    raw = (raw or '').strip()
    if not raw:
        raise ValueError('no URL given')
    if not raw.startswith(('http://', 'https://')):
        raw = 'https://' + raw
    parts = urlparse(raw)
    if not parts.hostname:
        raise ValueError(f'not a valid URL: {raw!r}')
    return raw


def _prompt(label: str, default: str) -> str:
    try:
        answer = input(f'{label} [{default}]: ').strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(1)
    return answer or default


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='webcrawler',
        description=(
            'Crawl one host and report admin/hidden URLs, SQL injection '
            'candidates and XSS input sinks. Only crawl sites you are '
            'authorized to test.'
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        'url', nargs='?',
        help='Base URL to crawl. If omitted, you are prompted for it.',
    )
    parser.add_argument(
        '-d', '--delay', type=float, default=2.0,
        help='Seconds to wait between requests (politeness delay).',
    )
    parser.add_argument(
        '--ram-limit', type=int, default=400, metavar='MB',
        help='Offload state to disk once the Python process exceeds this RSS.',
    )
    parser.add_argument(
        '-o', '--output-dir', default='.',
        help='Directory for the JSON report/state file.',
    )
    parser.add_argument(
        '--timeout', type=float, default=10.0,
        help='Per-request timeout in seconds.',
    )
    parser.add_argument(
        '--max-pages', type=int, default=None,
        help='Stop after this many pages (default: no limit).',
    )
    parser.add_argument(
        '--max-page-bytes', type=int, default=2_000_000,
        help='Truncate page bodies larger than this many bytes.',
    )
    parser.add_argument(
        '--checkpoint-every', type=int, default=50,
        help='Save state every N pages (0 disables periodic checkpoints).',
    )
    parser.add_argument(
        '--min-static-links', type=int, default=3,
        help='Below this link count, a JS-looking page escalates to Selenium.',
    )
    parser.add_argument(
        '--no-selenium', action='store_true',
        help='Disable the Selenium/Chrome fallback entirely.',
    )
    parser.add_argument(
        '--ignore-robots', action='store_true',
        help='Do not consult robots.txt (use only on sites you are allowed to test).',
    )
    parser.add_argument(
        '--fresh', action='store_true',
        help='Ignore any saved state and start a new crawl.',
    )
    parser.add_argument(
        '--resume', action='store_true',
        help='Resume a saved crawl without prompting.',
    )
    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='Suppress per-page progress (the final summary is still printed).',
    )
    parser.add_argument(
        '--version', action='version', version=f'%(prog)s {__version__}',
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.url is None:
        if not sys.stdin.isatty():
            parser.error('a URL is required when running non-interactively')
        args.url = _prompt('URL to crawl', 'https://example.com')

    try:
        base_url = _normalize_base_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    crawler = WebCrawler(
        base_url,
        delay=args.delay,
        ram_limit_mb=args.ram_limit,
        output_dir=args.output_dir,
        timeout=args.timeout,
        max_pages=args.max_pages,
        max_page_bytes=args.max_page_bytes,
        checkpoint_every=args.checkpoint_every,
        min_static_links=args.min_static_links,
        allow_selenium=not args.no_selenium,
        respect_robots=not args.ignore_robots,
        fresh=args.fresh,
        resume=True if args.resume else None,
        quiet=args.quiet,
    )
    crawler.crawl()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
