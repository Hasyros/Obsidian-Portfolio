import sys, io, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

with open('xss-finder.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Find the PAYLOADS array
start = html.index('const PAYLOADS = [')
end = html.index('];', start) + 2
array_part = html[start:end]
lines = array_part.split('\n')

# 1. Detect template literals (backtick strings) with unescaped ${ inside
dollar_braces = []
for lineno, line in enumerate(lines):
    if 'payload:' not in line:
        continue
    # Find backtick-delimited string on this line (simple heuristic)
    tl_match = re.search(r'payload:\s*`(.*)`', line)
    if not tl_match:
        continue
    content = tl_match.group(1)
    # Find ${ not preceded by backslash
    for m in re.finditer(r'(?<!\\)\$\{', content):
        dollar_braces.append((lineno, content[:120]))
        break

print("Template literals with unescaped ${...}: " + str(len(dollar_braces)))
for lineno, content in dollar_braces[:10]:
    print("  Line " + str(lineno) + ": " + content)

# 2. Look for any raw <script> that is NOT inside a JS string
# Strategy: find positions of <script in the array_part that are not inside quotes
print("\nSearching for executable HTML tags outside string literals in PAYLOADS...")

# Quick check: search for patterns like <script> on a line that is NOT a payload value line
exec_tags = []
for lineno, line in enumerate(lines):
    stripped = line.strip()
    # Skip comment lines and payload/desc/tag lines (they're string values)
    if stripped.startswith('//') or not stripped:
        continue
    # These lines contain string values
    string_lines = ('payload:', 'desc:', 'tags:', 'subcategory:', 'category:', 'browsers:', 'id:', 'interaction:')
    is_string_line = any(stripped.startswith(s) for s in string_lines)
    # Check for executable patterns NOT in string context
    if not is_string_line:
        if re.search(r'<script\b|onerror\s*=|onload\s*=', stripped, re.IGNORECASE):
            exec_tags.append((lineno, stripped[:120]))

print("Potentially executable tags outside string context: " + str(len(exec_tags)))
for lineno, content in exec_tags[:10]:
    print("  Line " + str(lineno) + ": " + content)

# 3. Count <script and </script in whole file
all_opens = [(m.start(), html[m.start():m.start()+40]) for m in re.finditer(r'<script\b', html, re.IGNORECASE)]
all_closes = [(m.start(), html[m.start():m.start()+15]) for m in re.finditer(r'</script>', html, re.IGNORECASE)]
print("\nAll <script> open tags in file: " + str(len(all_opens)))
for pos, ctx in all_opens:
    print("  pos " + str(pos) + ": " + repr(ctx))
print("All </script> close tags in file: " + str(len(all_closes)))
for pos, ctx in all_closes:
    print("  pos " + str(pos) + ": " + repr(ctx))

# 4. Look for multiline template literals containing ${
print("\nChecking multiline template literals...")
# Extract the whole PAYLOADS array and find all template literals
tl_pattern = re.compile(r'payload:\s*`((?:[^`\\]|\\.)*)` ', re.DOTALL)
tl_matches = tl_pattern.findall(array_part)
print("Multiline backtick payload strings found: " + str(len(tl_matches)))
for i, m in enumerate(tl_matches):
    if '${' in m and not re.search(r'\\\$\{', m):
        print("  Match " + str(i) + " has raw ${}: " + repr(m[:100]))

print("\nDone.")
