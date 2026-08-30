#!/usr/bin/env python3
"""lexicon_gate.py — Zero-Bandaid Law at the vocabulary level.
Scans markdown/text for banned phrases from governance/CANONICAL_LEXICON.yaml.
Exit 1 if any banned phrase is found. A failing first run is correct behavior:
the exit code is the checklist."""
import sys, pathlib, yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

def main(roots):
    lex = yaml.safe_load(open(ROOT / "governance" / "CANONICAL_LEXICON.yaml"))
    banned = lex["banned"]
    hits = []
    for root in roots:
        for p in pathlib.Path(root).rglob("*"):
            if p.suffix.lower() not in (".md", ".txt", ".html") or not p.is_file():
                continue
            if ".git" in p.parts:
                continue
            text = p.read_text(errors="ignore")
            low = text.lower()
            for b in banned:
                if b["phrase"].lower() in low:
                    line_no = next(i + 1 for i, l in enumerate(text.splitlines())
                                   if b["phrase"].lower() in l.lower())
                    hits.append((str(p), line_no, b))
    if hits:
        print("LEXICON GATE: FAIL — Zero-Bandaid violations\n")
        for path, ln, b in hits:
            print(f"  {path}:{ln}")
            print(f"    banned:  \"{b['phrase']}\"")
            print(f"    why:     {b['why']}")
            print(f"    say:     {b['say_instead']}\n")
        print(f"{len(hits)} violation(s). Fix the text, not the gate.")
        return 1
    print(f"LEXICON GATE: PASS — {sum(1 for r in roots for p in pathlib.Path(r).rglob('*') if p.suffix.lower() in ('.md','.txt','.html') and '.git' not in p.parts)} files clean")
    return 0

if __name__ == "__main__":
    roots = sys.argv[1:] or [str(ROOT)]
    sys.exit(main(roots))
