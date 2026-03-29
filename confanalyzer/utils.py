
import json
from collections import Counter
from threading import Lock
from html import escape
from colorama import Fore, Style, init

init(autoreset=True)

_issues = []
_seen = set()
_lock = Lock()

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}
LEVEL_COLORS = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.LIGHTRED_EX,
    "medium": Fore.YELLOW,
    "warning": Fore.YELLOW,
    "low": Fore.GREEN,
    "info": Fore.CYAN,
}
LEVEL_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "warning": 3, "low": 1, "info": 0}

def clear_issues() -> None:
    with _lock:
        _issues.clear()
        _seen.clear()

def add_issue(level: str, msg: str, file_path: str, line_no=None, matched_line=None, fingerprint=None) -> None:
    with _lock:
        if fingerprint and fingerprint in _seen:
            return
        if fingerprint:
            _seen.add(fingerprint)
        _issues.append({
            "level": level,
            "msg": msg,
            "file": file_path,
            "line_no": line_no,
            "matched_line": matched_line,
        })

def _snapshot(show_low: bool = False):
    with _lock:
        items = list(_issues)
    if not show_low:
        items = [x for x in items if x["level"] in ("critical", "high", "medium")]
    return sorted(items, key=lambda x: (LEVEL_ORDER.get(x["level"], 99), x["file"], x.get("line_no") or 0, x["msg"]))

def _calc_risk(issues):
    counts = Counter(item["level"] for item in issues)
    return sum(LEVEL_WEIGHTS.get(level, 0) * count for level, count in counts.items()), counts

def print_results(json_out: bool = False, html_out: bool = False, show_low: bool = False) -> None:
    issues = _snapshot(show_low=show_low)
    risk_score, counts = _calc_risk(issues)

    if json_out:
        print(json.dumps({"issues": issues, "risk_score": risk_score, "counts": dict(counts)}, indent=2))
        return

    if html_out:
        with open("report.html", "w", encoding="utf-8") as report:
            report.write("<html><head><meta charset='utf-8'><title>ConfAnalyzer Report</title></head><body>")
            report.write("<h1>ConfAnalyzer Report</h1>")
            report.write(f"<p>Risk Score: {risk_score}</p>")
            report.write("<p>" + ", ".join(f"{escape(level.upper())}: {count}" for level, count in sorted(counts.items(), key=lambda x: LEVEL_ORDER.get(x[0], 99))) + "</p>")
            if not issues:
                report.write("<p>No likely vulnerabilities found.</p>")
            else:
                report.write("<ul>")
                for item in issues:
                    report.write("<li>")
                    report.write(f"<strong>{escape(item['level'].upper())}</strong> - {escape(item['file'])}")
                    if item.get("line_no") is not None:
                        report.write(f": line {item['line_no']}")
                    report.write(f" - {escape(item['msg'])}")
                    if item.get("matched_line"):
                        report.write(f"<br><code>{escape(item['matched_line'])}</code>")
                    report.write("</li>")
                report.write("</ul>")
            report.write("</body></html>")
        print("[+] HTML report generated: report.html")
        return

    if not issues:
        print(Fore.GREEN + Style.BRIGHT + "[SAFE] No likely vulnerabilities found.")
        return

    for item in issues:
        color = LEVEL_COLORS.get(item["level"], Fore.WHITE)
        line_part = f":{item['line_no']}" if item.get("line_no") is not None else ""
        print(color + f"[{item['level'].upper()}] {item['file']}{line_part}: {item['msg']}")
        if item.get("matched_line"):
            print(Fore.WHITE + f"    -> {item['matched_line']}")

    summary_parts = []
    for level in ("critical", "high", "medium"):
        if counts.get(level):
            summary_parts.append(f"{level.upper()}: {counts[level]}")
    if show_low and counts.get("low"):
        summary_parts.append(f"LOW: {counts['low']}")
    if summary_parts:
        print(Fore.WHITE + "\nSummary: " + ", ".join(summary_parts))

    print(Fore.CYAN + Style.BRIGHT + f"Risk Score: {risk_score}")
