"""
Tool-coverage adjudication pipeline (fully automatic, runs on Claude Code).

Stages
  extract     find each finding's own section in its audit-report PDF
  adjudicate  send each finding (with its original text) to Claude via `claude -p`
  report      majority verdicts, agreement, and a results spreadsheet
  all         the three stages in order

Quick start (inside this folder):
    pip install pymupdf pandas openpyxl
    claude            # once, to sign in to your Claude account, then exit
    python pipeline.py all --pdf-dir "C:/path/to/audit_pdfs" --limit 30
    python pipeline.py all --pdf-dir "C:/path/to/audit_pdfs"

Every stage is resumable: run the same command again and finished work is
skipped. Nothing is ever sent anywhere except through your own Claude Code.
"""

import argparse
import csv
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
FINDINGS_CSV = HERE / "findings_for_adjudication.csv"
TEMPLATE = HERE / "adjudicator_prompt_template.txt"
CATALOG_JSONL = HERE / "tool_detector_reference_set_v2.jsonl"
WORK = HERE / "work" / "findings_for_adjudication"
TEXT_CACHE = HERE / "work" / "pdf_text"
EXTRACTED_CSV = WORK / "findings_with_text.csv"
MAX_SECTION_CHARS = 8000

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


# ----------------------------------------------------------------- helpers
def norm(s):
    s = (s or "").replace("\ufb01", "fi").replace("\ufb02", "fl").replace("\ufb00", "ff")
    s = s.replace("\u2019", "'").replace("\u2018", "'").replace("\u201c", '"').replace("\u201d", '"')
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def name_key(filename):
    return re.sub(r"[^a-z0-9]", "", Path(filename).stem.lower())


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    tmp = Path(str(path) + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)


# ----------------------------------------------------------------- stage 1
def pdf_to_lines(pdf_path):
    """Extract text once per PDF and cache it."""
    TEXT_CACHE.mkdir(parents=True, exist_ok=True)
    cache = TEXT_CACHE / (name_key(pdf_path.name) + ".txt")
    if cache.exists():
        return cache.read_text(encoding="utf-8").split("\n")
    try:
        import pymupdf as fitz
    except ImportError:
        try:
            import fitz
        except ImportError:
            sys.exit("PyMuPDF is missing. Run: pip install pymupdf")
    doc = fitz.open(str(pdf_path))
    text = "\n".join(page.get_text("text") for page in doc)
    doc.close()
    lines = [re.sub(r"[ \t]+", " ", l).strip() for l in text.split("\n")]
    lines = [l for l in lines if l]
    cache.write_text("\n".join(lines), encoding="utf-8")
    return lines


TOC_RE = re.compile(r"\.{4,}|\u2026{2,}|(\s\.){4,}")
BODY_WORDS = ("description", "impact", "recommendation", "remediation", "severity",
              "exploit", "proof of concept", "mitigation", "likelihood", "attack",
              "scenario", "difficulty", "target")
NEAR_WORDS = ("description", "severity", "impact", "risk", "difficulty", "target",
              "category", "likelihood", "context", "file(s)", "files")
STOP = {"the", "a", "an", "of", "in", "to", "for", "and", "or", "is", "be", "can",
        "could", "may", "on", "by", "with", "when", "if", "are", "not", "no", "via"}
EXCERPT_CHARS = 7000


def stem(w):
    for suf in ("ation", "ing", "ed", "es", "s"):
        if len(w) > len(suf) + 3 and w.endswith(suf):
            return w[: -len(suf)]
    return w


def toks(s):
    return {stem(w) for w in norm(s).split() if w not in STOP and len(w) > 2}


def strip_code_prefix(title):
    return re.sub(r"^\s*([A-Z]{1,8}(?:-[A-Z0-9]+)*-?\d+[.:)]?|\[[^\]]+\]|\d+(?:\.\d+)*\.?)\s*",
                  "", title)


def find_section(lines, title):
    """Locate the finding in the report and return a generous excerpt.

    The excerpt deliberately over-covers (it can include a neighbouring
    finding); the adjudication prompt tells the model to use only the part
    about this finding and to report whether the excerpt was relevant.
    Returns (excerpt, status, score) with status exact | token | not_found.
    """
    core = strip_code_prefix(title)
    t_norm = norm(core) or norm(title)
    t_toks = toks(core) or toks(title)
    if not t_norm:
        return "", "not_found", 0.0
    nl = [norm(l) for l in lines]
    key = t_norm[:60]

    cands = []
    for i in range(len(lines)):
        if not nl[i]:
            continue
        win = " ".join(nl[i:i + 4])
        if key and key in win and (key[:20] in " ".join(nl[i:i + 2])):
            cands.append((i, "exact", 1.0))
        elif t_toks:
            wt = toks(" ".join(lines[i:i + 3]))
            ov = len(t_toks & wt) / len(t_toks)
            if ov >= 0.6 and len(t_toks) >= 2:
                cands.append((i, "token", round(ov, 2)))
    if not cands:
        return "", "not_found", 0.0

    def quality(c):
        i, status, score = c
        ahead = " ".join(nl[i:i + 45])
        near = " ".join(l.lower() for l in lines[i:i + 10])
        body = sum(1 for w in BODY_WORDS if w in ahead)
        near_hits = sum(1 for w in NEAR_WORDS if w in near)
        toc = sum(1 for l in lines[max(0, i - 3):i + 6] if TOC_RE.search(l))
        short = sum(1 for l in lines[i:i + 12] if len(l) < 25)
        heading = 2 if re.match(r"^(\W*[\w.-]{1,12}[.:)\]]?\s+)?" + re.escape(key[:15]), nl[i]) else 0
        return ((1.0 if status == "exact" else score) * 3 + body + 2 * near_hits
                + heading - 2 * toc - 0.3 * short)

    exact = [c for c in cands if c[1] == "exact"]
    best = max(exact or cands, key=quality)
    i, status, score = best
    # A token match often lands inside the finding body, after its heading,
    # so start further back to keep the heading and description.
    start = max(0, i - (2 if status == "exact" else 15))
    out, size = [], 0
    for line in lines[start:]:
        out.append(line)
        size += len(line) + 1
        if size >= EXCERPT_CHARS:
            out.append("[...excerpt ends]")
            break
    return "\n".join(out), status, score


def stage_extract(args):
    WORK.mkdir(parents=True, exist_ok=True)
    pdf_dir = Path(args.pdf_dir)
    if not pdf_dir.is_dir():
        sys.exit(f"PDF folder not found: {pdf_dir}")
    index = {}
    for p in pdf_dir.rglob("*"):
        if p.suffix.lower() == ".pdf":
            index.setdefault(name_key(p.name), p)
    print(f"{len(index)} PDFs found under {pdf_dir}")

    findings = read_csv(FINDINGS_CSV)
    if args.limit:
        findings = findings[: args.limit]
    done = {}
    if EXTRACTED_CSV.exists():
        done = {r["finding_id"]: r for r in read_csv(EXTRACTED_CSV)}

    keys = list(index.keys())
    by_pdf = defaultdict(list)
    for r in findings:
        by_pdf[r["source_pdf"]].append(r)

    results, missing_pdfs = [], set()
    n = 0
    for src, rows in by_pdf.items():
        k = name_key(src)
        path = index.get(k)
        if path is None:
            # Only accept a near-identical name (e.g. spaces vs underscores are
            # already normalised away). Report names such as "X Audit Report -
            # QuillAudits" differ by one word, so a loose match would silently
            # pick the wrong report; anything else is reported as missing.
            close = difflib.get_close_matches(k, keys, n=2, cutoff=0.98)
            path = index[close[0]] if len(close) == 1 else None
        lines = None
        for r in rows:
            n += 1
            if r["finding_id"] in done and done[r["finding_id"]].get("extraction_status"):
                results.append(done[r["finding_id"]])
                continue
            row = dict(r)
            if path is None:
                missing_pdfs.add(src)
                row.update(original_text="", extraction_status="pdf_missing", extraction_score=0)
            else:
                if lines is None:
                    try:
                        lines = pdf_to_lines(path)
                    except Exception as e:
                        print(f"  could not read {path.name}: {e}")
                        lines = []
                text, status, score = find_section(lines, r["bug_title"]) if lines else ("", "pdf_unreadable", 0)
                row.update(original_text=text, extraction_status=status, extraction_score=score)
            results.append(row)
        if n % 200 < len(rows):
            print(f"  {n}/{len(findings)} findings processed")

    fields = list(findings[0].keys()) + ["original_text", "extraction_status", "extraction_score"]
    write_csv(EXTRACTED_CSV, results, fields)
    c = Counter(r["extraction_status"] for r in results)
    print("Extraction status:", dict(c))
    if missing_pdfs:
        (WORK / "missing_pdfs.txt").write_text("\n".join(sorted(missing_pdfs)), encoding="utf-8")
        print(f"{len(missing_pdfs)} PDFs not found; list saved to work/missing_pdfs.txt")


# ----------------------------------------------------------------- stage 2
def extract_json(text):
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    start = text.find("{")
    if start == -1:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def build_catalog_text():
    lines = []
    for l in open(CATALOG_JSONL, encoding="utf-8"):
        if l.strip():
            e = json.loads(l)
            tag = "[CODE]" if e.get("vulnerable_pattern") else "[TEXT]"
            lines.append(f"[{e['id']}] {tag} {e['tool']} | {e['title']}: {e['description']}")
    return "\n".join(lines)


def build_prompt_parts(row, template, catalog):
    full = (template.replace("<<FULL_CATALOG>>", catalog)
            .replace("<<BUG_TITLE>>", row["bug_title"])
            .replace("<<SOURCE_PDF>>", row["source_pdf"])
            .replace("<<ORIGINAL_FINDING_TEXT>>", row.get("original_text", ""))
            .replace("<<JUSTIFICATION>>", row.get("justification", ""))
            .replace("<<CANDIDATE_IDS>>", row.get("candidate_ids", "")))
    idx = full.find("\nFINDING:\n")
    return full[:idx], full[idx + 1:]


LIMIT_HINTS = ("usage limit", "rate limit", "rate_limit", "limit reached", "overloaded",
               "429", "529", "try again later")


def call_claude(claude_bin, model, system_file, user_text, timeout=900):
    cmd = [claude_bin, "-p", "--model", model,
           "--system-prompt-file", system_file,
           "--disallowedTools", "*",
           "--max-turns", "1",
           "--output-format", "json",
           "--no-session-persistence"]
    proc = subprocess.run(cmd, input=user_text, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    out = (proc.stdout or "").strip()
    try:
        payload = json.loads(out) if out else {}
    except json.JSONDecodeError:
        payload = {"result": out}
    return proc.returncode, payload, (proc.stderr or "").strip()


def stage_adjudicate(args):
    if not EXTRACTED_CSV.exists():
        sys.exit("Run the extract stage first.")
    claude_bin = shutil.which("claude")
    if not claude_bin:
        sys.exit("The 'claude' command was not found. Install Claude Code and sign in first.")
    rows = read_csv(EXTRACTED_CSV)
    if args.limit:
        rows = rows[: args.limit]
    if args.skip_missing_text:
        rows = [r for r in rows if r.get("original_text")]

    template = TEMPLATE.read_text(encoding="utf-8")
    catalog = build_catalog_text()
    prefix, _ = build_prompt_parts(rows[0], template, catalog)
    fd, sys_file = tempfile.mkstemp(suffix="_system_prompt.txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(prefix)

    out_path = WORK / f"answers_{args.model.replace('/', '_')}.jsonl"
    done = set()
    if out_path.exists():
        for l in open(out_path, encoding="utf-8"):
            if l.strip():
                r = json.loads(l)
                if r.get("parsed") is not None:
                    done.add((r["finding_id"], r["run"]))
    jobs = [(r, run) for run in range(1, args.runs + 1) for r in rows
            if (r["finding_id"], run) not in done]
    print(f"{len(rows)} findings x {args.runs} run(s): {len(jobs)} calls to make, {len(done)} already done")

    lock = threading.Lock()
    pause_until = [0.0]
    counter = [0]

    def work(job):
        row, run = job
        _, suffix = build_prompt_parts(row, template, catalog)
        attempts = 0
        while True:
            wait = pause_until[0] - time.time()
            if wait > 0:
                time.sleep(wait)
            attempts += 1
            try:
                code, payload, err = call_claude(claude_bin, args.model, sys_file, suffix)
            except subprocess.TimeoutExpired:
                code, payload, err = 1, {}, "timeout"
            text = payload.get("result", "") if isinstance(payload, dict) else ""
            blob = (str(text) + " " + err).lower()
            if code != 0 or payload.get("is_error"):
                if any(h in blob for h in LIMIT_HINTS) and attempts <= 40:
                    with lock:
                        pause_until[0] = max(pause_until[0], time.time() + args.limit_wait_minutes * 60)
                        print(f"  usage limit or overload; pausing {args.limit_wait_minutes} min")
                    continue
                if attempts <= 3:
                    time.sleep(30)
                    continue
                rec = {"finding_id": row["finding_id"], "run": run, "model": args.model,
                       "error": (err or str(text))[:2000], "parsed": None}
            else:
                parsed = extract_json(text)
                rec = {"finding_id": row["finding_id"], "run": run, "model": args.model,
                       "models_used": list((payload.get("modelUsage") or {}).keys()),
                       "raw": text, "parsed": parsed,
                       "est_cost_usd": payload.get("total_cost_usd")}
                if parsed is None and attempts <= 2:
                    continue
            with lock:
                with open(out_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                counter[0] += 1
                v = rec["parsed"].get("verdict") if rec.get("parsed") else "FAILED"
                print(f"  [{counter[0]}/{len(jobs)}] {row['finding_id']} run {run}: {v}")
            return

    try:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            for fut in as_completed([ex.submit(work, j) for j in jobs]):
                fut.result()
    finally:
        os.remove(sys_file)
    print(f"Answers saved to {out_path}")


# ----------------------------------------------------------------- stage 3
def stage_report(args):
    rows = {r["finding_id"]: r for r in read_csv(EXTRACTED_CSV)}
    out_path = WORK / f"answers_{args.model.replace('/', '_')}.jsonl"
    if not out_path.exists():
        sys.exit("No answers yet. Run the adjudicate stage first.")
    answers = defaultdict(list)
    models_seen = set()
    for l in open(out_path, encoding="utf-8"):
        r = json.loads(l)
        if r.get("parsed"):
            answers[r["finding_id"]].append(r["parsed"])
            models_seen.update(r.get("models_used") or [])

    report = []
    for fid, parsed_list in answers.items():
        base = rows.get(fid, {})
        verdicts = [p.get("verdict") for p in parsed_list]
        top, n = Counter(verdicts).most_common(1)[0]
        rep = next(p for p in parsed_list if p.get("verdict") == top)
        report.append({
            "finding_id": fid,
            "bug_title": base.get("bug_title"),
            "source_pdf": base.get("source_pdf"),
            "pass1_tier": base.get("pass1_tier"),
            "extraction_status": base.get("extraction_status"),
            "final_verdict": top,
            "agreement": f"{n}/{len(verdicts)}",
            "all_verdicts": "; ".join(verdicts),
            "scope": rep.get("scope"),
            "type": rep.get("type"),
            "language_evidence": rep.get("language_evidence"),
            "severity": rep.get("severity"),
            "found_by_tool": rep.get("found_by_tool"),
            "covered_by": rep.get("covered_by"),
            "mechanism": rep.get("mechanism"),
            "matching": json.dumps(rep.get("matching"), ensure_ascii=False),
            "original_text": base.get("original_text", "")[:3000],
        })
    report.sort(key=lambda r: r["finding_id"])
    fields = list(report[0].keys())
    stem = f"results_{args.model.replace('/', '_')}"
    write_csv(WORK / f"{stem}.csv", report, fields)
    try:
        import pandas as pd
        pd.DataFrame(report).to_excel(WORK / f"{stem}.xlsx", index=False)
        print(f"Saved {WORK / (stem + '.xlsx')}")
    except Exception as e:
        print(f"(Excel export skipped: {e})")

    c = Counter(r["final_verdict"] for r in report)
    ext = Counter(r["extraction_status"] for r in report)
    lines = [f"Model(s) actually used: {', '.join(sorted(models_seen)) or 'unknown'}",
             f"Findings adjudicated: {len(report)}",
             "Final verdicts:"] + [f"  {k}: {v}" for k, v in c.most_common()] + \
            ["Extraction status of adjudicated findings:"] + [f"  {k}: {v}" for k, v in ext.most_common()]
    if any(int(r["agreement"].split("/")[1]) > 1 for r in report):
        unanimous = sum(1 for r in report if r["agreement"].split("/")[0] == r["agreement"].split("/")[1])
        lines.append(f"Unanimous across runs: {unanimous}/{len(report)}")
    summary = "\n".join(lines)
    (WORK / f"{stem}_summary.txt").write_text(summary, encoding="utf-8")
    print(summary)


# ----------------------------------------------------------------- main
def main():
    global FINDINGS_CSV, WORK, EXTRACTED_CSV
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage", choices=["extract", "adjudicate", "report", "all"])
    ap.add_argument("--findings", default=str(FINDINGS_CSV),
                    help="findings CSV (default: all 5,169; use findings_pilot.csv for the 30-item pilot)")
    ap.add_argument("--pdf-dir", help="folder that contains the audit-report PDFs (searched recursively)")
    ap.add_argument("--model", default="opus", help="Claude Code model alias or full model ID")
    ap.add_argument("--runs", type=int, default=1, help="independent runs per finding (3 for majority voting)")
    ap.add_argument("--workers", type=int, default=1, help="parallel calls (keep low on a subscription)")
    ap.add_argument("--limit", type=int, default=0, help="only the first N findings (for a pilot run)")
    ap.add_argument("--skip-missing-text", action="store_true",
                    help="do not adjudicate findings whose PDF section could not be extracted")
    ap.add_argument("--limit-wait-minutes", type=int, default=15)
    args = ap.parse_args()

    FINDINGS_CSV = Path(args.findings).resolve()
    if not FINDINGS_CSV.exists():
        sys.exit(f"Findings file not found: {FINDINGS_CSV}")
    WORK = HERE / "work" / FINDINGS_CSV.stem
    EXTRACTED_CSV = WORK / "findings_with_text.csv"
    WORK.mkdir(parents=True, exist_ok=True)

    if args.stage in ("extract", "all"):
        if not args.pdf_dir:
            sys.exit("--pdf-dir is required for the extract stage")
        stage_extract(args)
    if args.stage in ("adjudicate", "all"):
        stage_adjudicate(args)
    if args.stage in ("report", "all"):
        stage_report(args)


if __name__ == "__main__":
    main()
