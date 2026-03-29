from pathlib import Path
from confanalyzer.engine import run_engine
from confanalyzer.utils import clear_issues, _snapshot


def write_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_detects_password(tmp_path):
    clear_issues()
    f = write_file(tmp_path, "app.conf", "password = supersecret123\n")
    run_engine(str(f))
    issues = _snapshot(show_low=True)
    assert any("Hardcoded password-like value" in i["msg"] for i in issues)


def test_detects_api_key(tmp_path):
    clear_issues()
    f = write_file(tmp_path, "app.yaml", "api_key: ABCDEFG123456\n")
    run_engine(str(f))
    issues = _snapshot(show_low=True)
    assert any("Hardcoded API key-like value" in i["msg"] for i in issues)


def test_detects_secret(tmp_path):
    clear_issues()
    f = write_file(tmp_path, ".env", "secret_key=myrealjwtsecretvalue\n")
    run_engine(str(f))
    issues = _snapshot(show_low=True)
    assert any("Hardcoded secret-like value" in i["msg"] for i in issues)
