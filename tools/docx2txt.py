#!/usr/bin/env python3
"""Flatten a .docx report to plain text for reading or diffing.

Headings become Markdown '#' lines, tables become '| a | b |' rows (merged
cells are emitted once). Body order is preserved.

Usage:
    .venv/bin/python tools/docx2txt.py REPORT.docx OUT.txt
"""
import sys

import docx
from docx.table import Table
from docx.text.paragraph import Paragraph


def convert(path):
    d = docx.Document(path)
    out = []
    for child in d.element.body.iterchildren():
        t = child.tag.rsplit("}", 1)[-1]
        if t == "p":
            p = Paragraph(child, d)
            s = p.text.strip()
            if s:
                st = p.style.name if p.style is not None else ""
                heading = st.startswith("Heading") and st[-1:].isdigit()
                out.append(("#" * int(st[-1]) + " " if heading else "") + s)
        elif t == "tbl":
            for row in Table(child, d).rows:
                cells, prev = [], None
                for c in row.cells:
                    if c._tc is not prev:
                        cells.append(c.text.strip().replace("\n", " / "))
                    prev = c._tc
                out.append("| " + " | ".join(cells) + " |")
            out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    text = convert(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write(text)
    print(f"{sys.argv[2]}: {text.count(chr(10)) + 1} lines")
