import re, pathlib, sys
src = pathlib.Path("asset.html").read_text(encoding="utf-8")
m = re.search(r"<script[^>]*>([\\s\\S]*)</script>", src, flags=re.IGNORECASE)
if not m:
    print("SCRIPT NOT FOUND")
    sys.exit(1)
code = m.group(1)
try:
    compile(code, "asset.html", "exec")
    print("JS parse OK")
except SyntaxError as e:
    print("SyntaxError:", e.msg, "line", e.lineno, "col", e.offset)
    sys.exit(1)
