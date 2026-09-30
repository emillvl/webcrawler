"""Detection signatures: the crawler's pattern cheat sheet.

Every URL, parameter and DOM heuristic the crawler knows about lives in this
module. Keeping them here means ``webcrawler.py`` stays focused on crawling,
and the signatures can be reviewed, extended and unit-tested on their own.

This module performs no I/O and has no third-party dependencies.

Conventions
-----------
* ``ADMIN_PATH_REGEXES`` are ``re.Pattern`` objects matched with ``search``
  against the URL *path* (not the host, query or fragment). A match means the
  path resembles a known admin/login/back-office surface.
* ``SQLI_PARAM_NAMES`` are compared case-insensitively against query-string
  parameter names.
* ``*_FINGERPRINTS`` are lowercase substrings compared against a lowercased
  concatenation of an element's ``id`` and ``class`` attributes.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Admin / hidden URL paths
# ---------------------------------------------------------------------------

ADMIN_PATH_PATTERNS: tuple[str, ...] = (
    # Generic admin surfaces
    r'/admin(?:/|$)',
    r'/administrator(?:/|$)',
    r'/administration(?:/|$)',
    r'/webadmin(?:/|$)',
    r'/web-admin(?:/|$)',
    r'/siteadmin(?:/|$)',
    r'/admin_area(?:/|$)',
    r'/admin1(?:/|$)',
    r'/admin2(?:/|$)',
    r'/adm(?:/|$)',
    # Authentication flows
    r'/login(?:\.php|\.asp|\.aspx|\.html|\.jsp|/|$)',
    r'/signin(?:/|$)',
    r'/sign-in(?:/|$)',
    r'/log-in(?:/|$)',
    r'/logon(?:/|$)',
    r'/logout(?:/|$)',
    r'/signout(?:/|$)',
    r'/auth(?:/|$)',
    r'/authentication(?:/|$)',
    r'/register(?:/|$)',
    r'/signup(?:/|$)',
    r'/sign-up(?:/|$)',
    r'/forgot.?password(?:/|$)',
    r'/reset.?password(?:/|$)',
    r'/change.?password(?:/|$)',
    r'/account(?:/|$)',
    r'/accounts(?:/|$)',
    r'/oauth(?:/|$)',
    r'/sso(?:/|$)',
    r'/saml(?:/|$)',
    # Control panels and dashboards
    r'/panel(?:/|$)',
    r'/cpanel(?:/|$)',
    r'/whm(?:/|$)',
    r'/control(?:/|$)',
    r'/controlpanel(?:/|$)',
    r'/control.panel(?:/|$)',
    r'/dashboard(?:/|$)',
    r'/console(?:/|$)',
    r'/portal(?:/|$)',
    r'/hub(?:/|$)',
    r'/backend(?:/|$)',
    r'/back.end(?:/|$)',
    r'/backoffice(?:/|$)',
    r'/manager(?:/|$)',
    r'/management(?:/|$)',
    r'/manage(?:/|$)',
    r'/moderator(?:/|$)',
    r'/mod(?:/|$)',
    # CMS entry points
    r'/wp-admin(?:/|$)',
    r'/wp-login(?:\.php)?(?:/|$)',
    r'/wp-content/plugins',
    r'/wp-includes',
    r'/cms(?:/|$)',
    r'/joomla(?:/|$)',
    r'/drupal(?:/|$)',
    r'/typo3(?:/|$)',
    r'/magento(?:/|$)',
    # Database management UIs
    r'/phpmyadmin(?:/|$)',
    r'/phpmyadmin2(?:/|$)',
    r'/pma(?:/|$)',
    r'/myadmin(?:/|$)',
    r'/mysqladmin(?:/|$)',
    r'/pgadmin(?:/|$)',
    r'/adminer(?:\.php)?(?:/|$)',
    r'/db(?:/|$)',
    r'/database(?:/|$)',
    r'/dbadmin(?:/|$)',
    r'/db.admin(?:/|$)',
    r'/sql(?:/|$)',
    r'/sqlite(?:/|$)',
    r'/redis(?:/|$)',
    r'/mongo(?:/|$)',
    r'/elasticsearch(?:/|$)',
    # Hosting control panels
    r'/plesk(?:/|$)',
    r'/directadmin(?:/|$)',
    r'/webmail(?:/|$)',
    r'/mail(?:/|$)',
    # Server / health info
    r'/server.?status(?:/|$)',
    r'/server.?info(?:/|$)',
    r'/status(?:/|$)',
    r'/health(?:/|$)',
    r'/info(?:\.php)?(?:/|$)',
    r'/phpinfo(?:\.php)?(?:/|$)',
    r'/ping(?:/|$)',
    r'/actuator(?:/|$)',  # Spring Boot
    r'/metrics(?:/|$)',
    r'/env(?:/|$)',
    # Config, secrets and setup
    r'/config(?:/|$)',
    r'/configuration(?:/|$)',
    r'/settings(?:/|$)',
    r'/setup(?:/|$)',
    r'/install(?:ation)?(?:/|$)',
    r'/\.env(?:/|$)',
    r'/secrets(?:/|$)',
    r'/credentials(?:/|$)',
    r'/keys(?:/|$)',
    r'/private(?:/|$)',
    # Backups, logs and temp directories
    r'/backup(?:s)?(?:/|$)',
    r'/bak(?:/|$)',
    r'/old(?:/|$)',
    r'/archive(?:s)?(?:/|$)',
    r'/logs?(?:/|$)',
    r'/error.?log(?:s)?(?:/|$)',
    r'/tmp(?:/|$)',
    r'/temp(?:/|$)',
    r'/cache(?:/|$)',
    # Development, test and debug
    r'/test(?:ing|s)?(?:/|$)',
    r'/dev(?:/|$)',
    r'/development(?:/|$)',
    r'/staging(?:/|$)',
    r'/debug(?:/|$)',
    r'/trace(?:/|$)',
    r'/sandbox(?:/|$)',
    r'/demo(?:/|$)',
    r'/beta(?:/|$)',
    # File management
    r'/upload(?:s)?(?:/|$)',
    r'/files(?:/|$)',
    r'/media(?:/|$)',
    r'/assets(?:/|$)',
    r'/attachments(?:/|$)',
    r'/documents(?:/|$)',
    r'/ftp(?:/|$)',
    # Code / command execution
    r'/shell(?:/|$)',
    r'/cmd(?:/|$)',
    r'/command(?:/|$)',
    r'/exec(?:/|$)',
    r'/cgi.?bin(?:/|$)',
    r'/xmlrpc(?:\.php)?(?:/|$)',
    r'/api\.php(?:/|$)',
    r'/ajax\.php(?:/|$)',
    r'/eval(?:\.php)?(?:/|$)',
    r'/proc(?:/|$)',
    # API admin namespaces
    r'/api/admin',
    r'/api/v\d+/admin',
    r'/api/internal',
    r'/_internal',
    r'/api/debug',
    r'/api/test',
    r'/graphql(?:/|$)',
    r'/graphiql(?:/|$)',
    r'/_ah/',  # Google App Engine admin
)

ADMIN_PATH_REGEXES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE) for pattern in ADMIN_PATH_PATTERNS
)

# ---------------------------------------------------------------------------
# Query-string parameter names that commonly carry SQL-injectable input
# ---------------------------------------------------------------------------

SQLI_PARAM_NAMES: frozenset[str] = frozenset({
    # Primary key / record selection
    'id', 'item', 'item_id', 'itemid', 'item_no',
    'product', 'product_id', 'productid', 'prod', 'prod_id', 'prod_no',
    'cat', 'cat_id', 'catid', 'category', 'category_id', 'subcategory_id',
    'page', 'page_id', 'pageid', 'p',
    'post', 'post_id', 'postid', 'pid',
    'article', 'article_id', 'articleid', 'aid',
    'user', 'user_id', 'userid', 'uid', 'account_id', 'member_id', 'profile_id',
    'news', 'news_id', 'newsid', 'nid',
    'record', 'record_id', 'row', 'entry', 'entry_id',
    'doc', 'document', 'document_id',
    'num', 'no', 'number', 'nr', 'idx', 'index',
    'ref', 'ref_id', 'id_user', 'id_product', 'id_cat', 'id_order',
    # Forum / community identifiers
    'tid', 'fid', 'bid', 'cid', 'mid', 'gid', 'sid', 'rid',
    # Transactions
    'order_id', 'orderid', 'transaction_id', 'invoice_id', 'payment_id',
    # Search / query text
    'search', 'query', 'q', 's', 'keyword', 'keywords', 'kw',
    'term', 'terms', 'text', 'txt', 'find', 'lookup', 'fetch', 'match',
    'filter_text', 'search_term', 'search_query',
    # Filter / sort / ORDER BY injection
    'filter', 'filters', 'where', 'having', 'group',
    'sort', 'sortby', 'sort_by', 'orderby', 'order_by', 'order_dir',
    'by', 'column', 'col', 'field', 'asc', 'desc', 'direction',
    # View / display mode
    'view', 'display', 'show', 'format', 'layout',
    'mode', 'tab', 'type', 'kind', 'style',
    # File / path (LFI and SQLi overlap)
    'file', 'filename', 'file_name',
    'path', 'filepath', 'file_path',
    'dir', 'directory', 'folder',
    'include', 'inc', 'load', 'read', 'open',
    'template', 'tpl', 'theme', 'skin', 'lang_file',
    # Action / command dispatch
    'action', 'act', 'do', 'task', 'cmd', 'command', 'op', 'func', 'method', 'call',
    # Language / locale
    'lang', 'language', 'locale', 'country', 'region',
    # Navigation / redirect (SSRF and open-redirect overlap)
    'return', 'redirect', 'url', 'goto', 'next', 'back', 'location', 'redir', 'dest',
    # Personal identifiers
    'name', 'fname', 'lname', 'username', 'uname', 'email', 'mail', 'phone', 'address',
    # Numeric / range / pagination
    'price', 'min_price', 'max_price', 'cost', 'amount', 'qty', 'quantity', 'stock',
    'start', 'offset', 'limit', 'count', 'per_page', 'skip', 'step',
    # Date / time
    'year', 'month', 'day', 'date', 'time',
    'from', 'to', 'from_date', 'to_date', 'start_date', 'end_date',
    # E-commerce / catalog attributes
    'color', 'colour', 'size', 'weight', 'brand', 'model', 'maker',
    'tag', 'tags', 'label', 'code', 'sku', 'barcode', 'upc', 'ean',
    'coupon', 'promo', 'discount', 'voucher', 'gift_code',
    # Tokens / keys commonly passed to database lookups
    'token', 'key', 'hash', 'session', 'sess', 'ticket', 'secret',
    'salt', 'checksum', 'nonce', 'serial',
})

# ---------------------------------------------------------------------------
# Tracking parameters stripped during URL normalisation so the same page is
# not crawled repeatedly under different campaign URLs.
# ---------------------------------------------------------------------------

TRACKING_PARAMS: frozenset[str] = frozenset({
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'utm_id', 'utm_name', 'utm_reader', 'utm_creative_format',
    'gclid', 'dclid', 'gbraid', 'wbraid', 'fbclid', 'msclkid', 'yclid',
    'mc_cid', 'mc_eid', 'igshid', 'twclid', 'ttclid', 'ref_src', 'ref_url',
    '_ga', '_gl', 'vero_conv', 'vero_id', 'oly_anon_id', 'oly_enc_id',
})

# ---------------------------------------------------------------------------
# XSS input sinks
# ---------------------------------------------------------------------------

# Input types that accept free text and are worth reviewing for reflection.
TEXT_INPUT_TYPES: frozenset[str] = frozenset({
    'text', 'search', 'email', 'url', 'tel', 'number', 'password',
})

# Input types with no meaningful text reflection.
SKIP_INPUT_TYPES: frozenset[str] = frozenset({
    'hidden', 'submit', 'button', 'radio', 'checkbox',
    'file', 'image', 'range', 'color', 'date', 'datetime-local',
    'month', 'week', 'time', 'reset',
})

# Lowercase id/class fragments that identify a rich-text / WYSIWYG editor.
RICH_EDITOR_FINGERPRINTS: tuple[str, ...] = (
    # TinyMCE
    'mce-content-body', 'tinymce', 'mce_editable', 'mce-edit-area',
    # CKEditor 4 and 5
    'cke_editable', 'ckeditor', 'ck-editor', 'ck-content',
    # Quill
    'ql-editor', 'ql-container',
    # Froala
    'fr-element', 'froala-editor', 'fr-box',
    # Summernote
    'note-editable', 'summernote',
    # Draft.js (React)
    'drafteditor-content', 'public-drafteditor-content', 'drafteditor-root',
    # ProseMirror / Tiptap
    'prosemirror', 'tiptap-editor',
    # CodeMirror 5 and 6
    'codemirror', 'cm-editor', 'cm-content',
    # Ace Editor
    'ace_editor', 'ace-editor', 'ace_text-input',
    # SlateJS
    'slate-editor', 'slateeditor',
    # WMD / PageDown (StackExchange)
    'wmd-input', 'wmd-preview',
    # EasyMDE / SimpleMDE
    'easymde', 'simplemde',
    # Redactor
    'redactor-editor', 'redactor-box', 'redactor-layer',
    # Trumbowyg
    'trumbowyg-editor', 'trumbowyg-box',
    # MediumEditor
    'medium-editor-element',
    # Jodit
    'jodit_wysiwyg', 'jodit-wysiwyg', 'jodit-container',
    # Squire
    'squire-editor',
    # Lexical (Meta)
    'contenteditable__root', 'lexical-editor',
    # Milkdown
    'milkdown-editor', 'milkdown',
    # Toast UI Editor
    'toastui-editor',
    # Wysihtml5 / bootstrap-wysiwyg
    'wysiwyg', 'wysihtml5-editor', 'bootstrap-wysiwyg',
    # Generic / legacy labels
    'rich-text-editor', 'richtext', 'htmleditor', 'html-editor',
    'text-editor', 'content-editable', 'wys-editor',
)

# Lowercase id/class fragments that identify a user-content / comment surface.
COMMENT_SECTION_FINGERPRINTS: tuple[str, ...] = (
    # Generic comment blocks
    'comment', 'comments', 'comment-form', 'commentbox', 'comment-box',
    'comment-section', 'comment-area', 'comment-thread', 'comment-list',
    'add-comment', 'leave-comment', 'post-comment', 'write-comment',
    'new-comment', 'submit-comment',
    # Replies
    'respond', 'reply', 'replies', 'reply-form', 'reply-box',
    # Discussions / threads
    'discussion', 'discuss', 'thread', 'forum-thread',
    # Feedback
    'feedback', 'feedbackform', 'feedback-form', 'feedback-box',
    # Reviews and ratings
    'review', 'reviews', 'review-form', 'write-review', 'add-review',
    # Guest books
    'guestbook', 'guest-book', 'guestbook-form',
    # Forums / message boards
    'forum', 'forum-post', 'forum-reply', 'newthread', 'message-board',
    # Direct messages / chat
    'message', 'messages', 'messagebox', 'message-box',
    'shoutbox', 'shout', 'shout-box',
    'livechat', 'live-chat', 'chat', 'chatbox', 'chat-box',
    'livemessage', 'chat-input',
    # Support / helpdesk
    'helpdesk', 'help-desk', 'support-ticket', 'ticket-form', 'open-ticket',
    'contact-form', 'contactform', 'contact-us',
    'enquiry', 'inquiry', 'enquire',
    # Testimonials / social walls
    'testimonial', 'testimonials',
    'newsfeed', 'activity-feed', 'timeline',
    # Surveys / polls
    'survey', 'poll', 'questionnaire', 'quiz',
    # Annotations / inline notes
    'annotation', 'sticky-note', 'inline-comment',
    # Third-party comment widgets
    'disqus', 'disqus-thread',      # Disqus
    'fb-comments',                  # Facebook Comments
    'utterances',                   # GitHub-based comments
    'hyvor-talk',                   # Hyvor Talk
    'remark42',                     # Remark42
    'isso-thread',                  # Isso
    'commento',                     # Commento
)
