#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def real_main(args):
    if args.verbose:
        log.setLevel(logging.DEBUG)
    log.debug(f"tool args: {args}")


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dylibify")
    parser.add_argument("-i", "--in", type=Path, required=True, help="Input Mach-O executable")
    parser.add_argument("-o", "--out", type=Path, required=True, help="Output Mach-O dylib")
    parser.add_argument(
        "-d",
        "--dylib-path",
        help="Path for LC_ID_DYLIB command. e.g. @executable_path/Frameworks/libfoo.dylib",
    )
    platform_args = parser.add_mutually_exclusive_group()
    platform_args.add_argument("-I", "--ios", action="store_true", help="Patch platform to iOS")
    platform_args.add_argument("-M", "--macos", action="store_true", help="Patch platform to macOS")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    return parser


def main():
    real_main(get_arg_parser().parse_args())


if __name__ == "__main__":
    main()
