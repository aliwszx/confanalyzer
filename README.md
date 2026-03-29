
# ConfAnalyzer v1.0.2

ConfAnalyzer is a lightweight and practical configuration analysis tool designed to identify likely security misconfigurations and exposed secrets in system and application config files.

It is built with a focus on:
- real-world usability
- low noise
- fast scanning
- simple CLI experience

## Features

- Detects hardcoded:
  - passwords
  - API keys
  - secrets
- Supports common config formats:
  - `.conf`, `.ini`, `.env`, `.yaml`, `.yml`, `.cfg`, `.cnf`
- Recursive scanning
- JSON and HTML output
- Multi-threaded scanning
- Severity-based risk score
- Security hints for findings
- Cleaner default filtering for docs, tests, snapshots, runtime noise, and package noise

## Installation

```bash
git clone https://github.com/aliwszx/confanalyzer.git
cd confanalyzer
chmod +x install.sh
./install.sh
```

## Usage

Basic scan:

```bash
confanalyzer /etc
```

Recursive scan:

```bash
confanalyzer /etc --deep
```

Broader scan:

```bash
confanalyzer / --deep --all-paths
```

JSON output:

```bash
confanalyzer /etc --json
```

HTML report:

```bash
confanalyzer /etc --html
```

Sample test:

```bash
confanalyzer ./samples --deep
```

## Example Output

```text
[HIGH] /app/config.yaml:12: Hardcoded API key-like value
    -> api_key: ABC***56

[MEDIUM] /etc/app.conf:45: Hardcoded password-like value
    -> password = sup***23

Summary: HIGH: 1, MEDIUM: 1
Risk Score: 9
```

## Notes

- Findings should always be reviewed manually.
- Some detections may reflect default/demo credentials rather than active secrets.
- Sample files are included to help validate detection behavior locally.

## Author

**aliwszx**  
GitHub: https://github.com/aliwszx

## License

MIT License
