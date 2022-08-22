#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path

from dylibify.patch import dylibify

log = logging.getLogger("dylibify")


def real_main(args):
    if args.verbose:
        log.setLevel(logging.DEBUG)
    log.debug(f"tool args: {args}")
    dylibify(
        args.in_path,
        args.out_path,
        args.dylib_path,
        args.remove_dylib,
        args.auto_remove_dylibs,
        args.remove_info_plist,
        args.ios,
        args.macos,
    )


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dylibify")
    parser.add_argument("-i", "--in", dest="in_path", required=True, help="Input Mach-O executable")
    parser.add_argument("-o", "--out", dest="out_path", required=True, help="Output Mach-O dylib")
    parser.add_argument(
        "-d",
        "--dylib-path",
        help="Path for LC_ID_DYLIB command. e.g. @executable_path/Frameworks/libfoo.dylib",
    )
    parser.add_argument("-r", "--remove-dylib", action="append", help="Remove dylib dependency")
    parser.add_argument(
        "-R",
        "--auto-remove-dylibs",
        action="store_true",
        help="Automatically remove unavailable dylib dependencies",
    )
    parser.add_argument(
        "-P", "--remove-info-plist", action="store_true", help="Remove __info_plist section"
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
