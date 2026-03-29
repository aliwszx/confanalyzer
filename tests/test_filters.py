from pathlib import Path
from confanalyzer.engine import run_engine
from confanalyzer.utils import clear_issues, _snapshot


def write_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_skips_xrdp_ask(tmp_path):
    clear_issues()
    f = write_file(tmp_path, "xrdp.ini", "password=ask\n")
    run_engine(str(f))
    issues = _snapshot(show_low=True)
    assert len(issues) == 0


def test_skips_placeholder(tmp_path):
    clear_issues()
    f = write_file(tmp_path, "config.yaml", "api_key: <YOUR KEY>\n")
    run_engine(str(f))
    issues = _snapshot(show_low=True)
    assert len(issues) == 0


def test_skips_template_value(tmp_path):
    clear_issues()
    f = write_file(tmp_path, "config.yaml", "password: {{ PASSWORD }}\n")
    run_engine(str(f))
    issues = _snapshot(show_low=True)
    assert len(issues) == 0
