#!/usr/bin/env python3

import argparse


def real_main(args):
    return


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dylibify")
    return parser


def main():
    real_main(get_arg_parser().parse_args())


if __name__ == "__main__":
    main()
