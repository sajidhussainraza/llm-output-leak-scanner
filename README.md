# LLM Output Leak Scanner

A dependency-free Python CLI that scans LLM-generated text (or any text)
for leaked PII and secrets, reports each finding with a severity, and
produces a redacted copy that is safe to log, share, or store.

## Why this exists

Large language models can repeat sensitive data from their prompts, tool
outputs, or training context: email addresses, phone numbers, API keys,
tokens, and private keys. Logging or publishing that output unchanged
turns a model mistake into a real exposure. This tool is the output-side
guardrail: run it on model output before it reaches logs, tickets, or
published content.

## What it detects

| Finding | Severity |
|---|---|
| Private key block | critical |
| AWS access key, JWT, API key / secret, password, SSN-like number, credit-card-like number | high |
| Email address, phone number | medium |

Credit-card candidates must pass the Luhn check, so dates, IDs, and
phone numbers are not flagged as cards. All detection is pattern-based
and fully offline: no network calls, no data leaves the machine.

## Usage

```bash
python leak_scanner.py output.txt
python leak_scanner.py output.txt --redact redacted.txt
echo "my key is AKIAIOSFODNN7EXAMPLE" | python leak_scanner.py -
python leak_scanner.py --json output.txt
```

Exit code: `0` = clean, `1` = findings, `2` = usage/input error.

## Example

```text
$ python leak_scanner.py examples/sample-output.txt
4 finding(s), worst severity: high
  line 3: [medium] Email address: jane.doe@example.com
  line 3: [medium] Phone-number-like string: 0300-1234567
  line 4: [high] AWS access key ID: AKIAIOSFODNN7EXAMPLE
  line 5: [high] JSON Web Token: eyJhbGciOiJIUzI1NiJ9...
Counts: aws_access_key=1, email=1, jwt=1, phone=1
```

## Tests

```bash
python -m unittest discover tests -v
```

## Files

- `leak_scanner.py` — the scanner (standard library only)
- `tests/test_leak_scanner.py` — 7 unit tests
- `examples/sample-output.txt` — sample LLM output with planted leaks
  (the AWS key shown is AWS's documented example key, not a real secret)

## Limitations

Pattern matching catches known formats, not meaning: it can miss
well-obfuscated secrets and can flag legitimate-looking strings. Treat
its output as a triage aid, rotate any real secret it finds, and review
high-severity findings by hand.

## Author

Sajid Hussain Raza — University Cybersecurity Lecturer, AI Security
Engineer and AI Red Teamer, Director and Co-founder of Cyber Legends,
Lahore. https://cyberlegends.org
