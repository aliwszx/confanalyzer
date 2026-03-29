
import hashlib
import os
import re
from confanalyzer.rules import RULES
from confanalyzer.utils import add_issue

RELEVANT_FILENAMES = {
    ".env", ".git/config", "sshd_config", "ssh_config", "nginx.conf", "apache2.conf",
    "httpd.conf", "config.php", "database.yml", "settings.py", "config.yaml",
}
RELEVANT_EXTENSIONS = {".env", ".conf", ".cfg", ".ini", ".yaml", ".yml", ".cnf"}

BLACKLIST_PATH_PARTS = [
    "/etc/alternatives/", "/etc/xdg/", "/etc/X11/", "/etc/java-", "/etc/ssl/",
    "/etc/dictionaries", "/etc/rc0.d/", "/etc/rc1.d/", "/etc/rc2.d/", "/etc/rc3.d/",
    "/etc/rc4.d/", "/etc/rc5.d/", "/etc/rc6.d/", "/etc/rcS.d/",
]

HARD_SKIP_PATH_PARTS = [
    "/usr/share/doc/", "/usr/share/man/", "/examples/", "/example/", "/tests/", "/test/",
    "/testdata/", "/spec/", "/spec/dummy/", "/vendor/", "/site-packages/", "/dist-packages/",
    "/timeshift/snapshots/", "/steamlinuxruntime", "/steamrt", "/flatpak/runtime/",
    "/var/lib/docker/overlay2/", "/root/go/pkg/mod/", "/usr/lib/ssl/", "/files/etc/pki/tls/",
    "/cache/", "/tmp/", "/var/tmp/", "/usr/share/powershell-empire/empire/server/modules/",
    "/usr/share/powershell-empire/empire/test/", "/usr/lib/dradis/spec/",
]

SOFT_SKIP_PATH_PARTS = ["/usr/share/metasploit-framework/"]
BLACKLIST_BASENAMES = {"nsswitch.conf", "openssl.cnf"}
COMMENT_PREFIXES = ("#", ";", "//")
HIGH_CONFIDENCE_PATH_HINTS = ("dradis", "empire/server/config", "smtp", "theharvester", "api-keys", "/etc/", "/opt/", "/srv/", "/var/www/")

PLACEHOLDER_VALUES = {
    "<your key>", "<your_key>", "<apikey>", "<api_key>", "<secret>", "<token>",
    "changeme", "change_me", "example", "example123", "password", "passwd",
    "secret", "username", "admin", "test", "testing", "demo", "foobar", "baz",
    "pazzw0rd", "yourpassword", "your_secret", "your-api-key", "your_api_key",
}

SKIP_VALUES = {
    "", "ask", "asksame", "prompt", "interactive", "<your key>", "<your_key>",
    "<apikey>", "<api_key>", "<secret>", "<token>", '""', "''",
}

LOW_CONFIDENCE_PATTERNS = [r"^<.*>$", r"^\$\{.*\}$", r"^your[_ -]?(key|token|secret|password)$", r"^example.*$"]
TEMPLATE_PATTERNS = [r"^\{\{.*\}\}$", r"^\{\%.*\%\}$", r"^\$\{\{.*\}\}$", r"^<.*>$"]
DEFAULT_CREDENTIAL_VALUES = {"scanit!", "admin123", "root", "toor", "password123", "empire_password"}

def is_binary(file_path: str) -> bool:
    try:
        with open(file_path, "rb") as handle:
            return b"\x00" in handle.read(2048)
    except OSError:
        return True

def is_relevant_file(file_path: str, all_paths: bool = False) -> bool:
    lowered = file_path.replace("\\", "/").lower()
    if any(part in lowered for part in BLACKLIST_PATH_PARTS):
        return False
    if any(part in lowered for part in HARD_SKIP_PATH_PARTS):
        return False
    if not all_paths and any(part in lowered for part in SOFT_SKIP_PATH_PARTS):
        return False

    basename = os.path.basename(lowered)
    if basename in BLACKLIST_BASENAMES:
        return False
    if "/usr/share/powershell-empire/" in lowered and "/server/config.yaml" not in lowered:
        return False

    if basename in RELEVANT_FILENAMES:
        return True
    return any(lowered.endswith(ext) for ext in RELEVANT_EXTENSIONS)

def strip_comment_lines(content: str) -> str:
    cleaned = []
    for line in content.splitlines():
        if line.strip().startswith(COMMENT_PREFIXES):
            continue
        cleaned.append(line)
    return "\n".join(cleaned)

def normalize_value(value: str) -> str:
    return value.strip().strip('"').strip("'").strip(";").strip().lower()

def preview_value(raw_value: str) -> str:
    value = raw_value.strip().strip('"').strip("'").strip(";").strip()
    if len(value) <= 4:
        return value[0] + "***" if value else "***"
    if len(value) <= 8:
        return value[:2] + "***" + value[-1]
    return value[:3] + "***" + value[-2:]

def sanitize_match_line(line: str) -> str:
    patterns = [
        r'(?i)(password\s*[:=]\s*)(.+)',
        r'(?i)(db_password\s*[:=]\s*)(.+)',
        r'(?i)(admin_password\s*[:=]\s*)(.+)',
        r'(?i)(api[_-]?key\s*[:=]\s*)(.+)',
        r'(?i)(apikey\s*[:=]\s*)(.+)',
        r'(?i)(access[_-]?key\s*[:=]\s*)(.+)',
        r'(?i)(secret_key\s*[:=]\s*)(.+)',
        r'(?i)(client_secret\s*[:=]\s*)(.+)',
        r'(?i)(jwt_secret\s*[:=]\s*)(.+)',
        r'(?i)(secret\s*[:=]\s*)(.+)',
    ]
    sanitized = " ".join(line.strip().split())

    def repl(match):
        return match.group(1) + preview_value(match.group(2))

    for pattern in patterns:
        sanitized = re.sub(pattern, repl, sanitized)
    return sanitized[:220]

def is_placeholder(value: str) -> bool:
    normalized = normalize_value(value)
    return normalized in PLACEHOLDER_VALUES or any(re.match(p, normalized) for p in LOW_CONFIDENCE_PATTERNS)

def is_template_value(value: str) -> bool:
    normalized = normalize_value(value)
    return any(re.match(p, normalized) for p in TEMPLATE_PATTERNS)

def is_meaningful_value(raw_value) -> bool:
    if raw_value is None:
        return False
    value = normalize_value(raw_value)
    return bool(value) and not value.endswith(":")

def infer_severity(file_path: str, rule: dict, raw_value=None):
    lowered_path = file_path.lower()
    default_level = rule["default_level"]

    if raw_value is None:
        return default_level, None

    value = normalize_value(raw_value)

    if value in SKIP_VALUES:
        return None, None
    if is_placeholder(value):
        return None, None
    if is_template_value(value):
        return None, None
    if value in ("true", "false", "yes", "no", "on", "off", "~", "null", "none"):
        return None, None
    if value.startswith("${") and value.endswith("}"):
        return None, None
    if "xrdp" in lowered_path and value == "ask":
        return None, None

    if value in DEFAULT_CREDENTIAL_VALUES:
        return "medium", "Default/demo credential detected"

    if any(hint in lowered_path for hint in HIGH_CONFIDENCE_PATH_HINTS):
        if default_level == "high":
            return "critical", None
        if default_level == "medium":
            return "high", None

    if len(value) >= 20 and default_level == "medium":
        return "high", None

    return default_level, None

def make_fingerprint(rule_name: str, normalized_value: str, message: str) -> str:
    key = f"{rule_name}|{normalized_value}|{message}".encode("utf-8", "ignore")
    return hashlib.sha256(key).hexdigest()

def run_engine(file_path: str, show_hints: bool = False, all_paths: bool = False) -> None:
    if not is_relevant_file(file_path, all_paths=all_paths):
        return
    if is_binary(file_path):
        return

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
    except OSError:
        return

    content = strip_comment_lines(content)

    for rule in RULES:
        matched = False
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, content):
                raw_value = match.group(match.lastindex) if rule.get("kind") == "value" and match.lastindex else None
                if rule.get("kind") == "value" and not is_meaningful_value(raw_value):
                    continue

                level, label = infer_severity(file_path, rule, raw_value)
                if level is None:
                    continue

                line_no = content[:match.start()].count("\n") + 1
                raw_line = match.group(0).strip()
                display_line = sanitize_match_line(raw_line)

                message = rule["name"]
                if label:
                    message = f"{message} ({label})"
                if show_hints:
                    message = f"{message} | Hint: {rule['hint']}"

                normalized_value = normalize_value(raw_value) if raw_value is not None else "flag"
                add_issue(
                    level=level,
                    msg=message,
                    file_path=file_path,
                    line_no=line_no,
                    matched_line=display_line,
                    fingerprint=make_fingerprint(rule["id"], normalized_value, message),
                )
                matched = True
                break
            if matched:
                break
