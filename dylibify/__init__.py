import logging

from rich.logging import RichHandler

from dylibify import patch, tool

_log = logging.getLogger("dylibify")
_log.setLevel(logging.INFO)
_log.addHandler(RichHandler(show_time=False))

__version__ = "0.1.0"
