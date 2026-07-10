#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Build a bulk payload JS snippet from raw source files.

Reads every *.txt in the current directory, cleans/dedupes/categorizes
each line, and emits a JSON array of [payload, category, sub, tags, desc]
tuples. The JSON is safe to embed in a <script> tag because every '<',
'>' and '&' in payload strings is escaped as \\uXXXX.
"""
import os, re, json, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
HERE = os.path.dirname(os.path.abspath(__file__))

# --------------------------- source handling ----------------------------

# Friendly source-name for each file
SRC_NAME = {
    'seclists_portswigger.txt':     'PortSwigger',
    'seclists_ofjaaah.txt':          'OFJAAAH',
    'seclists_payloadbox.txt':       'payloadbox',
    'seclists_fuzzing.txt':          'SecLists-Fuzz',
    'seclists_jhaddix.txt':          'Jhaddix',
    'seclists_mario.txt':            'Mario',
    'seclists_brutelogic.txt':       'BruteLogic',
    'seclists_rsnake.txt':           'RSnake',
    'seclists_somdev.txt':           'Somdev',
    'seclists_innerhtml.txt':        'innerht.ml',
    'seclists_polyglots.txt':        'Polyglots',
    'seclists_poly_dmiessler.txt':   'Dmiessler',
    'seclists_ende_h4k.txt':         'h4k EnDe',
    'seclists_ende_mario.txt':       'Mario EnDe',
    'seclists_ende_xssattacks.txt':  'xssAttacks',
    'seclists_no_parens.txt':        'No-Parens',
    'pbox_all_in_one.txt':            'payload-box',
    'pbox_basic_events.txt':          'payload-box evts',
    'pbox_basic_scripts.txt':         'payload-box scripts',
    'pbox_blind.txt':                 'payload-box blind',
    'pbox_fuzz.txt':                  'payload-box fuzz',
    'pbox_encoding.txt':              'payload-box encoding',
    'pbox_obfuscation.txt':           'payload-box obfusc',
    'pbox_csp.txt':                   'payload-box CSP',
    'pbox_angular.txt':               'AngularJS',
    'pbox_jquery.txt':                'jQuery',
    'pbox_react.txt':                 'React',
    'pbox_svelte.txt':                'Svelte',
    'pbox_vue.txt':                   'Vue.js',
    'pbox_polyglots.txt':             'payload-box poly',
    'pbox_cloudflare.txt':            'Cloudflare WAF',
    'pbox_modsec.txt':                'ModSecurity WAF',
    'pgaijin_payload.txt':            'pgaijin66',
    'kingofduck_easy.txt':            'KingOfDuck',
    'kingofduck_burp.txt':            'KingOfDuck Burp',
    'renwax_payloads.txt':            'RenwaX23',
    'renwax_without_parens.md':       'RenwaX23 NoParens',
    'awesome_xss.txt':                'awesome-xss',
    'patt_xss_md.txt':                'PayloadsAllTheThings',
}

# Which files contain MD/prose — need extra filtering
MD_FILES = {'awesome_xss.txt', 'patt_xss_md.txt', 'renwax_without_parens.md'}

# ---------------------------- categorization ----------------------------

def categorize(p):
    """Return (category, subcategory_hint, extra_tags) for a payload string."""
    pl = p.lower()
    tags = set()

    # Core category (one wins; order matters)
    cat = 'Miscellaneous'
    if '<script' in pl:
        cat = 'Script Injection'
    elif '<svg' in pl:
        cat = 'SVG Injection'
    elif '<img' in pl:
        cat = 'IMG Injection'
    elif '<iframe' in pl:
        cat = 'Iframe Injection'
    elif '<video' in pl or '<audio' in pl or '<source' in pl:
        cat = 'Media Injection'
    elif '<body' in pl or '<html' in pl:
        cat = 'Body/HTML Injection'
    elif '<input' in pl or '<textarea' in pl or '<select' in pl or '<button' in pl:
        cat = 'Form Element Injection'
    elif '<a ' in pl or '<a\t' in pl or '<a\n' in pl or pl.startswith('<a>') or '<a\t' in pl:
        cat = 'Anchor Injection'
    elif '<math' in pl:
        cat = 'MathML Injection'
    elif '<object' in pl or '<embed' in pl or '<applet' in pl:
        cat = 'Object/Embed Injection'
    elif '<link' in pl or '<meta' in pl:
        cat = 'Head Element Injection'
    elif '<base' in pl:
        cat = 'BASE Injection'
    elif '<marquee' in pl or '<details' in pl or '<table' in pl or '<form' in pl:
        cat = 'HTML Tag Injection'
    elif '<style' in pl or 'expression(' in pl or '-moz-binding' in pl:
        cat = 'CSS Injection'
    elif pl.startswith('javascript:') or pl.startswith('"javascript:') or pl.startswith("'javascript:") or ' javascript:' in pl or '=javascript:' in pl:
        cat = 'URI Scheme'
    elif pl.startswith('data:') or 'data:text/html' in pl:
        cat = 'Data URI'
    elif pl.startswith('vbscript:'):
        cat = 'VBScript URI'
    elif '${' in pl:
        cat = 'Template Literal'
    elif re.search(r'\bon[a-z]+\s*=', pl):
        cat = 'Attribute/Event Handler'
    elif '<' in pl and '>' in pl:
        cat = 'HTML Tag Injection'
    elif re.search(r'\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(', pl):
        cat = 'JavaScript Context'

    # Generic tags
    if 'alert(' in pl: tags.add('alert')
    if 'prompt(' in pl: tags.add('prompt')
    if 'confirm(' in pl: tags.add('confirm')
    if 'console.log' in pl: tags.add('console')
    if 'document.cookie' in pl: tags.add('cookie')
    if 'document.domain' in pl: tags.add('domain')
    if 'location=' in pl or 'location.href' in pl: tags.add('location')
    if 'eval(' in pl: tags.add('eval')
    if 'function(' in pl or 'function `' in pl: tags.add('Function')
    if 'atob(' in pl: tags.add('base64')
    if '.settimeout' in pl or 'settimeout(' in pl: tags.add('setTimeout')
    if 'setinterval(' in pl: tags.add('setInterval')
    if '.fromcharcode' in pl: tags.add('fromCharCode')
    if '.tostring(' in pl and ('30)' in pl or '36)' in pl or '32)' in pl): tags.add('radix')
    if '\\u00' in pl or '\\u{' in pl: tags.add('unicode')
    if re.search(r'\\x[0-9a-f]{2}', pl): tags.add('hex')
    if '&#' in pl: tags.add('html-entity')
    if '%3c' in pl or '%3e' in pl or '%22' in pl: tags.add('url-encoded')
    if '`' in pl: tags.add('backtick')
    if 'import(' in pl: tags.add('import')
    if 'fetch(' in pl: tags.add('fetch')
    if 'xmlhttprequest' in pl or 'xhr' in pl: tags.add('xhr')
    if 'angular' in pl or 'ng-' in pl or 'ng:' in pl: tags.add('angularjs')
    if '{{' in pl and '}}' in pl: tags.add('template-injection')
    if 'csp' in pl: tags.add('csp-bypass')
    if 'waf' in pl: tags.add('waf-bypass')

    # Event-handler specific tag
    m = re.search(r'\bon([a-z]+)\s*=', pl)
    if m:
        tags.add('on' + m.group(1))
        tags.add('event-handler')

    # "no-parens" heuristic: has alert but no '(' between alert and end
    if re.search(r'alert[\s`]', pl) and '(' not in pl.split('alert', 1)[1][:5]:
        tags.add('no-parens')
    if 'onerror' in pl:
        tags.add('auto-trigger')
    if 'onload' in pl:
        tags.add('auto-trigger')
    if 'autofocus' in pl and 'onfocus' in pl:
        tags.add('autofocus')

    # Structural tags from tag present
    for t in ('script', 'svg', 'img', 'iframe', 'input', 'body', 'video',
              'audio', 'marquee', 'details', 'math', 'style', 'link',
              'meta', 'object', 'embed', 'base', 'form', 'button',
              'textarea', 'source', 'track', 'isindex', 'keygen',
              'xmp', 'plaintext'):
        if '<' + t in pl:
            tags.add(t)

    return cat, tags


# --------------------------- line processing ---------------------------

def is_valid_payload(line):
    """Is this line a plausible payload?"""
    s = line.strip()
    if not s:
        return False
    if len(s) > 500 or len(s) < 3:
        return False
    # Reject lines that look like pure markdown/prose/log
    if s.startswith(('#', '//', '---', '===', '**', '> ', '- [')):
        return False
    if s.startswith('```') or s.endswith('```'):
        return False
    # Must contain *some* payload-ish character
    low = s.lower()
    has_payload_feature = (
        '<' in s
        or 'javascript:' in low
        or 'data:' in low and 'base64' in low
        or re.search(r'\bon[a-z]+\s*=', low)
        or 'alert(' in low
        or 'prompt(' in low
        or 'confirm(' in low
        or '${' in s
        or 'eval(' in low
        or '.innerhtml' in low
    )
    if not has_payload_feature:
        return False
    # Reject lines that are 100% URL
    if s.startswith(('http://', 'https://')) and ' ' not in s:
        return False
    # Reject obvious non-payload prose
    if re.fullmatch(r'[A-Za-z .,!?()\"\':;0-9-]+', s):
        return False
    return True


def extract_md_payloads(text):
    """Extract payloads from markdown files — only code blocks and inline code."""
    out = []
    # Fenced code blocks
    for m in re.finditer(r'```[a-z]*\n(.*?)```', text, re.DOTALL):
        for line in m.group(1).split('\n'):
            line = line.strip()
            if is_valid_payload(line):
                out.append(line)
    # Indented code blocks (4-space)
    for line in text.split('\n'):
        if line.startswith('    '):
            s = line.strip()
            if is_valid_payload(s):
                out.append(s)
    # Inline backtick code
    for m in re.finditer(r'`([^`\n]+)`', text):
        s = m.group(1).strip()
        if is_valid_payload(s):
            out.append(s)
    return out


def read_source(path):
    name = os.path.basename(path)
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            data = f.read()
    except Exception as e:
        print('!! failed to read', name, e, file=sys.stderr)
        return []
    if name in MD_FILES:
        return extract_md_payloads(data)
    return [line.strip() for line in data.split('\n') if is_valid_payload(line)]


# --------------------------- existing payload set ---------------------------

def load_existing_payloads(html_path):
    """Extract payload strings from the existing PAYLOADS array in xss-finder.html
    so we can avoid duplicating them."""
    with open(html_path, 'r', encoding='utf-8') as f:
        html = f.read()
    start = html.index('const PAYLOADS = [')
    end = html.index('\n];', start)
    array_part = html[start:end]
    # payload values are in backtick-delimited template literals `...`
    strings = []
    for m in re.finditer(r"payload:\s*`((?:\\.|[^`\\])*)`", array_part, re.DOTALL):
        s = m.group(1)
        # Unescape JS escapes we actually use
        s = s.replace('\\`', '`').replace('\\$', '$').replace('\\\\', '\\')
        strings.append(s)
    return set(strings)


# --------------------------- main ----------------------------------------

def main():
    # Read all files
    files = sorted(f for f in os.listdir(HERE) if f.endswith('.txt') or f.endswith('.md'))
    all_entries = []    # list of (payload, src_name)
    seen_raw = set()
    for fname in files:
        if fname not in SRC_NAME:
            continue
        src = SRC_NAME[fname]
        lines = read_source(os.path.join(HERE, fname))
        kept = 0
        for line in lines:
            # Normalize whitespace (keep internal, strip outer)
            line = line.strip()
            if not line:
                continue
            # key = case-sensitive for payload fidelity
            key = line
            if key in seen_raw:
                continue
            seen_raw.add(key)
            all_entries.append((line, src))
            kept += 1
        print(f'  {fname:40s} -> {kept:5d} unique payloads', file=sys.stderr)

    print(f'\nTotal raw unique: {len(all_entries)}', file=sys.stderr)

    # Dedup against existing 337 curated payloads
    html_path = os.path.join(os.path.dirname(HERE), 'xss-finder.html')
    existing = load_existing_payloads(html_path)
    print(f'Existing curated payloads: {len(existing)}', file=sys.stderr)
    all_entries = [(p, s) for (p, s) in all_entries if p not in existing]
    print(f'After removing existing: {len(all_entries)}', file=sys.stderr)

    # Build bulk JSON entries
    bulk = []
    for payload, src in all_entries:
        cat, tags = categorize(payload)
        # Extra source tag
        tags.add('bulk')
        tags.add(src.lower().replace(' ', '-').replace('.', ''))
        tags_list = sorted(tags)[:8]  # cap tags for size
        desc = f'Source: {src}'
        bulk.append([payload, cat, src, tags_list, desc])

    # Emit as JSON with all '<' escaped as \u003c (so the HTML parser
    # cannot interpret any script/comment pattern inside).
    raw_json = json.dumps(bulk, ensure_ascii=False, separators=(',', ':'))
    # Defensive escapes for embedding in <script>
    safe = (raw_json
            .replace('\\', '\\\\')    # we'll re-fix below
            )
    # Actually — json.dumps already escapes backslashes. We only need to
    # neutralize '<' so that </script> / <!-- / <script can never appear.
    raw_json = json.dumps(bulk, ensure_ascii=False, separators=(',', ':'))
    # Replace '<' with its \u003c unicode escape form (valid JSON).
    safe_json = raw_json.replace('<', '\\u003c')
    # Also replace U+2028 / U+2029 which break JS string literals
    safe_json = safe_json.replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')

    out_path = os.path.join(HERE, 'bulk.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(safe_json)

    print(f'\nWrote {len(bulk)} bulk payloads to {out_path}', file=sys.stderr)
    print(f'Size: {len(safe_json):,} bytes', file=sys.stderr)

    # Category distribution
    from collections import Counter
    c = Counter(e[1] for e in bulk)
    print('\nCategory distribution:', file=sys.stderr)
    for k, v in c.most_common():
        print(f'  {k:30s} {v:6d}', file=sys.stderr)


if __name__ == '__main__':
    main()
