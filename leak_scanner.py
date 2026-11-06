#!/usr/bin/env python3
"""LLM Output Leak Scanner.

Scan LLM-generated text (or any text) for leaked PII and secrets, report
each finding with a severity, and produce a redacted copy that is safe to
log, share, or store.

Detectors (all pattern-based, no network calls, no data leaves the machine):
  email, phone, credit-card-like number, AWS access key, generic API key,
  JWT, private-key block, password assignment, SSN-like number.

Usage:
    python leak_scanner.py output.txt
    python leak_scanner.py output.txt --redact redacted.txt
    echo "my key is AKIAIOSFODNN7EXAMPLE" | python leak_scanner.py -
    python leak_scanner.py --json output.txt

Exit code: 0 = clean, 1 = findings, 2 = usage/input error.
Only the Python standard library is required.
"""

import argparse
import json
import re
import sys

PATTERNS = [
    ("aws_access_key", "high",
     r"\bAKIA[0-9A-Z]{16}\b",
     "AWS access key ID"),
    ("private_key", "critical",
     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "Private key block"),
    ("jwt", "high",
     r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
     "JSON Web Token"),
    ("api_key", "high",
     r"\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
     "API key / secret assignment"),
    ("password", "high",
     r"\bpassword\s*[:=]\s*['\"]?\S+['\"]?",
     "Password in clear text"),
    ("credit_card", "high",
     r"\b(?:\d[ -]?){13,19}\b",
     "Credit-card-like number (verify: may be a false positive)"),
    ("email", "medium",
     r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
     "Email address"),
    ("phone", "medium",
     r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b",
     "Phone-number-like string"),
    ("ssn_like", "high",
     r"\b\d{3}-\d{2}-\d{4}\b",
     "SSN-like number"),
]

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _luhn_ok(digits):
    """Return True if the digit string passes the Luhn check."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def scan(text):
    """Scan text; return a list of finding dicts (line, type, severity, match)."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, severity, pattern, label in PATTERNS:
            for m in re.finditer(pattern, line, re.IGNORECASE):
                value = m.group(0)
                # Credit-card detector: only keep Luhn-valid digit runs,
                # so dates, IDs and phone numbers are not flagged as cards.
                if kind == "credit_card":
                    digits = re.sub(r"\D", "", value)
                    if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                        continue
                findings.append({
                    "line": lineno,
                    "type": kind,
                    "severity": severity,
                    "label": label,
                    "match": value[:80],
                })
    return findings


def redact(text):
    """Return text with every detected value replaced by [REDACTED:<type>]."""
    out = text
    for kind, _sev, pattern, _label in PATTERNS:
        def _repl(m, kind=kind):
            if kind == "credit_card":
                digits = re.sub(r"\D", "", m.group(0))
                if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                    return m.group(0)
            return f"[REDACTED:{kind}]"
        out = re.sub(pattern, _repl, out, flags=re.IGNORECASE)
    return out


def summarize(findings):
    """Return (worst_severity, counts_by_type) for a findings list."""
    worst = "clean"
    counts = {}
    for f in findings:
        counts[f["type"]] = counts.get(f["type"], 0) + 1
        if SEVERITY_RANK[f["severity"]] > SEVERITY_RANK.get(worst, 0):
            worst = f["severity"]
    return worst, counts


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan LLM output for leaked PII and secrets.")
    parser.add_argument("input", help="File to scan, or - for stdin")
    parser.add_argument("--redact", metavar="FILE",
                        help="Write a redacted copy to FILE")
    parser.add_argument("--json", action="store_true",
                        help="Print findings as JSON")
    args = parser.parse_args(argv)

    try:
        text = sys.stdin.read() if args.input == "-" else open(
            args.input, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 2

    findings = scan(text)
    worst, counts = summarize(findings)

    if args.json:
        print(json.dumps({"worst": worst, "counts": counts,
                          "findings": findings}, indent=2))
    else:
        if not findings:
            print("Clean: no PII or secrets detected.")
        else:
            print(f"{len(findings)} finding(s), worst severity: {worst}")
            for f in findings:
                print(f"  line {f['line']}: [{f['severity']}] "
                      f"{f['label']}: {f['match']}")
            print("Counts:", ", ".join(
                f"{k}={v}" for k, v in sorted(counts.items())))

    if args.redact:
        try:
            with open(args.redact, "w", encoding="utf-8") as fh:
                fh.write(redact(text))
            print(f"Redacted copy written to {args.redact}")
        except OSError as exc:
            print(f"error: cannot write {args.redact}: {exc}", file=sys.stderr)
            return 2

    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
