"""Offline unit tests for the crawler's pure logic.

Run from the repository root:

    python -m unittest discover -s tests -v

No network access is required.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import signatures  # noqa: E402
import webcrawler  # noqa: E402
from webcrawler import WebCrawler  # noqa: E402


class SignatureTests(unittest.TestCase):
    def test_admin_patterns_are_path_anchored(self):
        for pattern in signatures.ADMIN_PATH_PATTERNS:
            self.assertTrue(pattern.startswith('/'), pattern)

    def test_sqli_names_are_lowercase(self):
        for name in signatures.SQLI_PARAM_NAMES:
            self.assertEqual(name, name.lower(), name)

    def test_tracking_params_are_lowercase(self):
        for name in signatures.TRACKING_PARAMS:
            self.assertEqual(name, name.lower(), name)

    def test_fingerprints_are_lowercase_and_unique(self):
        for group in (
            signatures.RICH_EDITOR_FINGERPRINTS,
            signatures.COMMENT_SECTION_FINGERPRINTS,
        ):
            self.assertEqual(len(group), len(set(group)), 'duplicate fingerprint')
            for fingerprint in group:
                self.assertEqual(fingerprint, fingerprint.lower(), fingerprint)
                self.assertTrue(fingerprint, 'empty fingerprint')

    def test_no_overlap_between_skip_and_text_inputs(self):
        overlap = signatures.SKIP_INPUT_TYPES & signatures.TEXT_INPUT_TYPES
        self.assertEqual(overlap, set())


class UrlTests(unittest.TestCase):
    def setUp(self):
        self.crawler = WebCrawler('https://example.com', output_dir='.')

    def test_normalize_strips_fragment_and_tracking(self):
        raw = 'https://Example.com/Path?b=2&utm_source=news&a=1#frag'
        self.assertEqual(
            WebCrawler._normalize_url(raw),
            'https://example.com/Path?a=1&b=2',
        )

    def test_normalize_sorts_query_for_stable_keys(self):
        first = WebCrawler._normalize_url('https://example.com/x?b=2&a=1')
        second = WebCrawler._normalize_url('https://example.com/x?a=1&b=2')
        self.assertEqual(first, second)

    def test_normalize_keeps_blank_values(self):
        self.assertEqual(
            WebCrawler._normalize_url('https://example.com/x?debug'),
            'https://example.com/x?debug=',
        )

    def test_normalize_leaves_non_http_scheme_untouched(self):
        self.assertEqual(WebCrawler._normalize_url('mailto:a@b.com'), 'mailto:a@b.com')

    def test_same_domain(self):
        self.assertTrue(self.crawler._same_domain('https://example.com/a'))
        self.assertTrue(self.crawler._same_domain('http://example.com/a'))
        self.assertFalse(self.crawler._same_domain('https://www.example.com/a'))
        self.assertFalse(self.crawler._same_domain('https://other.com/a'))
        self.assertFalse(self.crawler._same_domain('mailto:a@b.com'))

    def test_constructor_canonicalizes_base_url(self):
        crawler = WebCrawler('example.com', output_dir='.')
        self.assertEqual(crawler.base_url, 'https://example.com/')
        self.assertEqual(crawler.host, 'example.com')


class FrontierTests(unittest.TestCase):
    def test_frontier_is_fifo_and_deduplicated(self):
        crawler = WebCrawler('https://example.com', output_dir='.', quiet=True)
        crawler.stack.extend([
            'https://example.com/a',
            'https://example.com/b',
        ])
        crawler.queued.update(crawler.stack)

        first = crawler.stack.popleft()
        crawler.queued.discard(first)
        self.assertEqual(first, 'https://example.com/a')

        candidate = 'https://example.com/b'
        if candidate not in crawler.visited and candidate not in crawler.queued:
            crawler.stack.append(candidate)
            crawler.queued.add(candidate)
        self.assertEqual(list(crawler.stack), ['https://example.com/b'])


class RedirectScopeTests(unittest.TestCase):
    @staticmethod
    def _response(status, location=None):
        response = Mock()
        response.status_code = status
        response.headers = {'Location': location} if location else {}
        response.close = Mock()
        return response

    @patch('webcrawler.requests.get')
    def test_same_host_redirect_is_followed(self, get):
        first = self._response(302, '/next')
        second = self._response(200)
        get.side_effect = [first, second]
        crawler = WebCrawler('https://example.com', output_dir='.', quiet=True)

        response, final_url, request_failed = crawler._request_static('https://example.com/start')

        self.assertIs(response, second)
        self.assertEqual(final_url, 'https://example.com/next')
        self.assertFalse(request_failed)
        self.assertEqual(get.call_count, 2)
        first.close.assert_called_once()

    @patch('webcrawler.requests.get')
    def test_cross_host_redirect_is_blocked_before_second_request(self, get):
        first = self._response(302, 'https://outside.example/path')
        get.return_value = first
        crawler = WebCrawler('https://example.com', output_dir='.', quiet=True)

        response, final_url, request_failed = crawler._request_static('https://example.com/start')

        self.assertIsNone(response)
        self.assertEqual(final_url, 'https://example.com/start')
        self.assertFalse(request_failed)
        self.assertEqual(get.call_count, 1)
        first.close.assert_called_once()

    @patch('webcrawler.requests.get')
    def test_network_failure_can_still_escalate_to_selenium(self, get):
        get.side_effect = webcrawler.requests.RequestException('boom')
        crawler = WebCrawler('https://example.com', output_dir='.', quiet=True)

        result = crawler._fetch_static('https://example.com/start')

        self.assertTrue(result.escalate)


class AdminPathTests(unittest.TestCase):
    def test_known_admin_paths_match(self):
        for url in (
            'https://x.com/admin',
            'https://x.com/admin/users',
            'https://x.com/wp-login.php',
            'https://x.com/phpmyadmin/',
            'https://x.com/.env',
            'https://x.com/testing',
            'https://x.com/api/v2/admin',
        ):
            self.assertIsNotNone(WebCrawler._match_admin_path(url), url)

    def test_innocent_paths_do_not_match(self):
        for url in (
            'https://x.com/',
            'https://x.com/products/42',
            'https://x.com/contest',
            'https://x.com/blog/administrator-notes',
        ):
            self.assertIsNone(WebCrawler._match_admin_path(url), url)


class SqliParamTests(unittest.TestCase):
    def test_flags_numeric_and_text_params(self):
        result = WebCrawler._sqli_params('https://x.com/p?id=42&q=hello')
        self.assertEqual(result['id'], {'value': '42', 'numeric': True})
        self.assertEqual(result['q'], {'value': 'hello', 'numeric': False})

    def test_param_names_are_case_insensitive(self):
        result = WebCrawler._sqli_params('https://x.com/p?ID=7')
        self.assertIn('ID', result)
        self.assertTrue(result['ID']['numeric'])

    def test_unrelated_params_are_ignored(self):
        self.assertEqual(WebCrawler._sqli_params('https://x.com/p?not_a_thing=1'), {})

    def test_blank_values_are_kept(self):
        result = WebCrawler._sqli_params('https://x.com/p?search=')
        self.assertIn('search', result)
        self.assertEqual(result['search']['value'], '')

    def test_float_is_numeric(self):
        self.assertTrue(WebCrawler._sqli_params('https://x.com/p?price=9.99')['price']['numeric'])
        self.assertFalse(WebCrawler._sqli_params('https://x.com/p?price=9abc')['price']['numeric'])


class HtmlAnalysisTests(unittest.TestCase):
    SAMPLE = """
    <html><body>
      <form method="post" action="/comment">
        <input type="text" name="author" id="author" class="field">
        <input type="hidden" name="csrf" value="token">
        <input type="email" name="email">
        <textarea name="body"></textarea>
        <div id="comment-section" class="comments">
          <div class="comment-form">Reply</div>
        </div>
        <div id="editor" class="ck-editor__editable" contenteditable="true"></div>
        <div contenteditable></div>
      </form>
    </body></html>
    """

    def test_detects_inputs_editors_and_comments(self):
        analysis = WebCrawler._analyse_html(self.SAMPLE)
        elements = {record['element'] for record in analysis['inputs']}
        self.assertIn('input[type=text]', elements)
        self.assertIn('input[type=email]', elements)
        self.assertIn('textarea', elements)
        self.assertIn('div[contenteditable]', elements)
        self.assertNotIn('input[type=hidden]', elements)

        self.assertTrue(analysis['rich_editors'])
        self.assertTrue(analysis['comment_sections'])
        self.assertEqual(len(analysis['post_forms']), 1)
        self.assertEqual(analysis['post_forms'][0]['action'], '/comment')

    def test_plain_page_has_no_sinks(self):
        analysis = WebCrawler._analyse_html('<html><body><p>hi</p></body></html>')
        self.assertEqual(analysis['total_text_inputs'], 0)
        self.assertEqual(analysis['rich_editors'], [])
        self.assertEqual(analysis['comment_sections'], [])
        self.assertEqual(analysis['post_forms'], [])

    def test_get_form_is_not_a_post_form(self):
        analysis = WebCrawler._analyse_html('<form method="get"><input name="q"></form>')
        self.assertEqual(analysis['post_forms'], [])

    def test_contenteditable_inherit_is_ignored(self):
        analysis = WebCrawler._analyse_html('<div contenteditable="inherit"></div>')
        self.assertEqual(analysis['total_text_inputs'], 0)


class StateTests(unittest.TestCase):
    def test_round_trip_and_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            crawler = WebCrawler('https://example.com', output_dir=tmp, quiet=True)
            crawler.visited.update({'https://example.com/', 'https://example.com/admin'})
            crawler.all_links.extend(['https://example.com/', 'https://example.com/admin'])
            crawler.findings['admin_pages'].append({
                'url': 'https://example.com/admin',
                'matched_pattern': '/admin(?:/|$)',
                'found_at': 'now',
            })
            self.assertTrue(crawler.save_state())

            # Re-analysing the same URL must not create a duplicate entry.
            crawler.findings['admin_pages'].append({
                'url': 'https://example.com/admin',
                'matched_pattern': '/admin(?:/|$)',
                'found_at': 'later',
            })
            self.assertTrue(crawler.save_state())

            resumed = WebCrawler('https://example.com', output_dir=tmp, quiet=True)
            self.assertTrue(resumed.load_state())
            self.assertEqual(len(resumed.all_links), 2)
            self.assertEqual(len(resumed.findings['admin_pages']), 1)

    def test_complete_state_is_not_resumed(self):
        with tempfile.TemporaryDirectory() as tmp:
            crawler = WebCrawler('https://example.com', output_dir=tmp, quiet=True)
            crawler.visited.add('https://example.com/')
            self.assertTrue(crawler.save_state(final=True))

            resumed = WebCrawler('https://example.com', output_dir=tmp, quiet=True)
            self.assertFalse(resumed.load_state())

    def test_missing_state_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            crawler = WebCrawler('https://example.com', output_dir=tmp, quiet=True)
            self.assertFalse(crawler.load_state())

    def test_corrupt_state_returns_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            crawler = WebCrawler('https://example.com', output_dir=tmp, quiet=True)
            with open(crawler.state_file, 'w', encoding='utf-8') as handle:
                handle.write('{not json')
            self.assertFalse(crawler.load_state())


class BaseUrlTests(unittest.TestCase):
    def test_scheme_is_added(self):
        self.assertEqual(webcrawler._normalize_base_url('example.com'), 'https://example.com')

    def test_existing_scheme_is_kept(self):
        self.assertEqual(webcrawler._normalize_base_url('http://example.com'), 'http://example.com')

    def test_invalid_urls_raise(self):
        for bad in ('', '   ', 'http://', 'https:///path'):
            with self.assertRaises(ValueError, msg=bad):
                webcrawler._normalize_base_url(bad)


if __name__ == '__main__':
    unittest.main()
