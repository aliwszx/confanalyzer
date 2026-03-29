
RULES = [
    {
        "id": "hardcoded-password",
        "name": "Hardcoded password-like value",
        "default_level": "medium",
        "hint": "Move credentials out of plaintext configs and rotate exposed values.",
        "kind": "value",
        "patterns": [
            r'(?im)^\s*(password|db_password|admin_password)\s*=\s*([^\s][^\n]*)\s*$',
            r'(?im)^\s*(password|db_password|admin_password)\s*:\s*["\']?([^\s"\'][^\n"\']*)["\']?\s*$',
        ],
    },
    {
        "id": "hardcoded-api-key",
        "name": "Hardcoded API key-like value",
        "default_level": "high",
        "hint": "Store keys in environment variables or a secret manager and rotate if real.",
        "kind": "value",
        "patterns": [
            r'(?im)^\s*(api[_-]?key|apikey|access[_-]?key)\s*=\s*([^\s][^\n]*)\s*$',
            r'(?im)^\s*(api[_-]?key|apikey|access[_-]?key)\s*:\s*["\']?([^\s"\'][^\n"\']*)["\']?\s*$',
        ],
    },
    {
        "id": "hardcoded-secret",
        "name": "Hardcoded secret-like value",
        "default_level": "high",
        "hint": "Remove hardcoded secrets and replace with managed secret injection.",
        "kind": "value",
        "patterns": [
            r'(?im)^\s*(secret|secret_key|client_secret|jwt_secret)\s*=\s*([^\s][^\n]*)\s*$',
            r'(?im)^\s*(secret|secret_key|client_secret|jwt_secret)\s*:\s*["\']?([^\s"\'][^\n"\']*)["\']?\s*$',
        ],
    },
    {
        "id": "ssh-root-login",
        "name": "SSH root login enabled",
        "default_level": "high",
        "hint": "Set PermitRootLogin to no unless there is a documented exception.",
        "kind": "flag",
        "patterns": [r"(?im)^\s*PermitRootLogin\s+yes\b"],
    },
    {
        "id": "ssh-password-auth",
        "name": "SSH password authentication enabled",
        "default_level": "medium",
        "hint": "Prefer key-based SSH authentication and restrict password auth.",
        "kind": "flag",
        "patterns": [r"(?im)^\s*PasswordAuthentication\s+yes\b"],
    },
    {
        "id": "directory-listing",
        "name": "Directory listing enabled",
        "default_level": "medium",
        "hint": "Disable directory indexing unless there is a specific operational need.",
        "kind": "flag",
        "patterns": [r"(?im)^\s*autoindex\s+on\b"],
    },
]
