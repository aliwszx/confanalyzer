
import argparse
from colorama import Fore, Style, init
from confanalyzer.scanner import scan_path

init(autoreset=True)


def banner() -> None:
    art = r"""
   ______            ____                  __
  / ____/___  ____  / __/___ _____  ____ _/ /_  ______  ___  _____
 / /   / __ \/ __ \/ /_/ __ `/ __ \/ __ `/ / / / /_  / / _ \/ ___/
/ /___/ /_/ / / / / __/ /_/ / / / / /_/ / / /_/ / / /_/  __/ /
\____/\____/_/ /_/_/  \__,_/_/ /_/\__,_/_/\__, / /___/\___/_/
                                         /____/
"""
    print(Fore.CYAN + Style.BRIGHT + art)
    print(Fore.WHITE + "ConfAnalyzer v1.0.2 - configuration analyzer")
    print(Fore.WHITE + "Author: aliwszx\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="confanalyzer",
        description="ConfAnalyzer v1.0.2 - configuration analyzer",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--deep", action="store_true", help="Recursively scan directories")
    parser.add_argument("--json", action="store_true", help="Print findings as JSON")
    parser.add_argument("--html", action="store_true", help="Write findings to report.html")
    parser.add_argument("--threads", type=int, default=5, help="Number of worker threads")
    parser.add_argument("--security-hints", action="store_true", help="Show remediation hints")
    parser.add_argument("--show-low", action="store_true", help="Include low-confidence findings")
    parser.add_argument("--all-paths", action="store_true", help="Include broader paths except hard-noise locations")
    parser.add_argument("--no-banner", action="store_true", help="Disable startup banner")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner and not args.json:
        banner()

    scan_path(
        path=args.path,
        deep=args.deep,
        json_out=args.json,
        html_out=args.html,
        threads=args.threads,
        show_hints=args.security_hints,
        show_low=args.show_low,
        all_paths=args.all_paths,
    )


if __name__ == "__main__":
    main()
