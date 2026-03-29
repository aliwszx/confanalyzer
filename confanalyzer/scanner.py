
import os
from concurrent.futures import ThreadPoolExecutor
from confanalyzer.engine import run_engine
from confanalyzer.utils import clear_issues, print_results


def _process_file(file_path: str, show_hints: bool, all_paths: bool) -> None:
    run_engine(file_path, show_hints, all_paths=all_paths)


def scan_path(path: str, deep: bool, json_out: bool, html_out: bool, threads: int, show_hints: bool, show_low: bool, all_paths: bool) -> None:
    clear_issues()
    files = []

    if os.path.isfile(path):
        files.append(path)
    else:
        for root, _, filenames in os.walk(path):
            for name in filenames:
                files.append(os.path.join(root, name))
            if not deep:
                break

    if not files:
        print_results(json_out=json_out, html_out=html_out, show_low=show_low)
        return

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        for file_path in files:
            executor.submit(_process_file, file_path, show_hints, all_paths)

    print_results(json_out=json_out, html_out=html_out, show_low=show_low)
