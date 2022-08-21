#!/usr/bin/env python3

import argparse
from pathlib import Path


def real_main(args):
    return


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dylibify")
    parser.add_argument("-i", "--in", type=Path, help="Input Mach-O executable")
    parser.add_argument("-o", "--out", type=Path, help="Output Mach-O dylib")
    parser.add_argument(
        "-d",
        "--dylib-path",
        help="Path for LC_ID_DYLIB command. e.g. @executable_path/Frameworks/libfoo.dylib",
    )
    platform_args = parser.add_mutually_exclusive_group()
    platform_args.add_argument("-I", "--ios", action="store_true", help="Patch platform to iOS")
    platform_args.add_argument("-M", "--macos", action="store_true", help="Patch platform to macOS")
    return parser


def main():
    real_main(get_arg_parser().parse_args())


if __name__ == "__main__":
    main()
