"""Render architecture-document-2page.md (+ the compact diagram) into the
2-page submission PDF.

    python docs/build_2page_pdf.py            # writes docs/AEGIS-Architecture-2page.html
    node   docs/print_pdf.mjs <html> <pdf>    # headless Chrome -> PDF

The diagram is inserted right after the "Pipeline" heading.
"""
import base64
import os

import markdown

HERE = os.path.dirname(os.path.abspath(__file__))
md = open(os.path.join(HERE, "architecture-document-2page.md"), encoding="utf-8").read()
# The italic note about the condensed version is for repo readers, not the printout.
md = "\n".join(l for l in md.splitlines() if not l.startswith("*(Condensed"))
body = markdown.markdown(md, extensions=["extra"])
img = base64.b64encode(open(os.path.join(HERE, "architecture-compact.png"), "rb").read()).decode()
body = body.replace(
    "<h2>Pipeline</h2>",
    f'<h2>Pipeline</h2><img class="diagram" src="data:image/png;base64,{img}" alt="AEGIS pipeline">',
    1,
)

html = f"""<!doctype html><html><head><meta charset="utf-8"><title>AEGIS - Architecture Document</title>
<style>
  @page {{ size: A4; margin: 13mm 14mm 12mm 14mm; }}
  body {{ font-family: "Segoe UI", Calibri, Arial, sans-serif; font-size: 9.6pt; line-height: 1.38; color: #1a1a1a; }}
  h1 {{ font-size: 16pt; color: #1F497D; margin: 0 0 1mm; }}
  h1 + p {{ margin-top: 0; color: #444; font-size: 9.5pt; }}
  h2 {{ font-size: 11pt; color: #1F497D; border-bottom: 1.2px solid #1F497D; padding-bottom: 0.6mm; margin: 3.2mm 0 1.4mm; }}
  p {{ margin: 0 0 1.6mm; text-align: justify; }}
  ol, ul {{ margin: 0 0 1.6mm; padding-left: 5mm; }}
  li {{ margin-bottom: 0.9mm; text-align: justify; }}
  li ul {{ margin-top: 0.8mm; }}
  code {{ font-family: Consolas, monospace; font-size: 8.4pt; background: #f1f4f8; padding: 0 0.6mm; border-radius: 1px; }}
  strong {{ color: #111; }}
  img.diagram {{ width: 100%; margin: 0.5mm 0 2mm; }}
</style></head><body>{body}</body></html>"""
out = os.path.join(HERE, "AEGIS-Architecture-2page.html")
open(out, "w", encoding="utf-8").write(html)
print(out)
