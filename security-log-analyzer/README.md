# Security Log Analyzer

A command-line Python project that analyzes authentication and system log files, summarizes common event levels, counts failed login attempts by IPv4 address, and flags addresses that meet a configurable threshold.

## Features

- Counts total non-empty log events.
- Counts Information, Warning, and Error entries.
- Detects common failed-login markers (`Failed login`, `LOGIN_FAILED`, and `authentication failure`).
- Counts failed login attempts by valid IPv4 address.
- Flags an IP when its failed-login count reaches the configured threshold (default: 4).
- Counts recognized successful-login markers separately.
- Prints matching error lines for investigation.
- Exports a report to JSON or CSV.
- Includes sample log files and automated unit tests.
- Uses only the Python standard library; no third-party dependencies are required.

> **Important:** An alert is a rule-based signal for investigation, not proof that an IP address is malicious. The parser uses common text patterns and may need adjustment for your operating system or application log format.

## Requirements

- Python 3.9 or newer recommended.
- No external packages are required.

## Project structure

```text
security-log-analyzer/
├── main.py
├── README.md
├── .gitignore
├── sample_logs/
│   ├── security.log
│   └── systemreal.log
└── tests/
    └── test_main.py
```

## Run the analyzer

Open a terminal in the project directory.

Analyze the included authentication sample:

```bash
python main.py --input sample_logs/security.log
```

On Windows, this also works on many installations:

```powershell
py main.py --input sample_logs/security.log
```

Analyze a system log:

```bash
python main.py --input sample_logs/systemreal.log
```

The default input filename is `security.log` in the current directory. Use `--input` to specify another file.

## Configure the alert threshold

Set the number of failed login attempts from one IP that triggers an alert:

```bash
python main.py --input sample_logs/security.log --threshold 5
```

The threshold must be a positive integer.

## Export reports

JSON:

```bash
python main.py --input sample_logs/security.log --format json
```

CSV:

```bash
python main.py --input sample_logs/security.log --format csv
```

Choose an output path:

```bash
python main.py --input sample_logs/security.log --format json --output reports.json
```

The JSON report contains the source filename, threshold, event summary, failed attempts by IP, alerts, and error lines. The CSV report contains normalized summary, IP-count, and alert rows.

## Run tests

From the project directory:

```bash
python -m unittest discover -s tests -v
```

The tests cover valid and invalid IPv4 extraction, failed-login counting, alert thresholds, and summary counters.

## Detection logic and limitations

- Matching is text-based and depends on the wording used by the source logs.
- Event-level counters are independent; one line can contribute to a severity count and an authentication-event count.
- Only valid IPv4 addresses are counted; IPv6 extraction is not implemented.
- Successful login events are counted but are not treated as suspicious solely because they contain an IP address.
- The tool does not block IP addresses, connect to a SIEM, or perform real-time monitoring.
- Large production logs may need streaming/reporting improvements for specific operational requirements.

## Safe use and sample data

Use only logs you own or are authorized to analyze. The bundled sample addresses are documentation ranges and are not intended to identify real systems. Do not commit real authentication logs, personal data, credentials, session tokens, or internal host details to a public repository. Review all files before publishing.

## Roadmap

Possible next improvements:
- Support Windows Event Log exports and additional Linux authentication formats.
- Add timestamps, date-range filtering, and severity levels.
- Add structured logging and more test cases.
- Build an optional Flask dashboard for browser-based demonstrations.
- Add CI checks with GitHub Actions.

## License

No license is included. Add a license file if you want to grant others specific rights to reuse or distribute this project.
