#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Inject the bulk JSON data island and the bulk loader IIFE into xss-finder.html."""
import os, sys, io, re

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
HERE = os.path.dirname(os.path.abspath(__file__))
HTML = os.path.join(os.path.dirname(HERE), 'xss-finder.html')
BULK = os.path.join(HERE, 'bulk.json')

with open(HTML, 'r', encoding='utf-8') as f:
    html = f.read()

with open(BULK, 'r', encoding='utf-8') as f:
    bulk_json = f.read()

# Safety: assert no HTML-sensitive patterns in the JSON
for pat in ['</script', '<!--', '<script', '<']:
    assert pat not in bulk_json, f'JSON contains unsafe pattern {pat!r}'

# ---------- 1. remove any previous injection (idempotent) ----------
# Remove an existing data island if we have already run this
html = re.sub(
    r'<script type="application/json" id="bulk-data">.*?</script>\s*',
    '',
    html,
    flags=re.DOTALL,
)
# Remove an existing IIFE we inserted earlier
html = re.sub(
    r'// ====== BULK-LOADER START ======.*?// ====== BULK-LOADER END ======\n?',
    '',
    html,
    flags=re.DOTALL,
)

# ---------- 2. inject the data island just before <script> ----------
marker_script = '<script>\n// ============================================================\n// XSS PAYLOAD DATABASE\n// ============================================================'
assert marker_script in html, 'main <script> marker not found'

data_island = (
    '<script type="application/json" id="bulk-data">'
    + bulk_json
    + '</script>\n\n'
)
html = html.replace(marker_script, data_island + marker_script, 1)

# ---------- 3. inject the bulk-loader IIFE after the PAYLOADS array ----------
# The existing HTML has:
#     ];
#
#     // ============================================================
#     // APPLICATION
# We insert between `];` and the APPLICATION comment.
app_marker = '];\n\n// ============================================================\n// APPLICATION'
assert app_marker in html, 'APPLICATION marker not found'

loader = """];

// ====== BULK-LOADER START ======
// Load ~11k additional payloads from the <script type="application/json"> island.
// The island's content is JSON with every '<' escaped as \\u003c so the HTML
// parser can never misinterpret it. JSON.parse decodes those back to real '<'.
(function loadBulkPayloads() {
  const el = document.getElementById('bulk-data');
  if (!el) return;
  let bulk;
  try {
    bulk = JSON.parse(el.textContent);
  } catch (e) {
    console.error('[xss-finder] Failed to parse bulk payload data:', e);
    return;
  }
  let nextId = PAYLOADS.length ? Math.max.apply(null, PAYLOADS.map(function (p) { return p.id; })) + 1 : 1;
  for (let i = 0; i < bulk.length; i++) {
    const e = bulk[i];
    PAYLOADS.push({
      id: nextId++,
      payload: e[0],
      category: e[1],
      subcategory: e[2] || 'Bulk',
      tags: e[3] || [],
      desc: e[4] || '',
      browsers: 'all',
      interaction: false,
    });
  }
})();
// ====== BULK-LOADER END ======

// ============================================================
// APPLICATION"""

html = html.replace(app_marker, loader, 1)

with open(HTML, 'w', encoding='utf-8') as f:
    f.write(html)

print(f'Injected. New file size: {len(html):,} bytes ({len(html)/1024/1024:.2f} MB)')
