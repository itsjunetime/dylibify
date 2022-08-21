import logging

from rich.logging import RichHandler

from dylibify import macho, patch, tool

_log = logging.getLogger(__name__)
_log.setLevel(logging.INFO)
_log.addHandler(RichHandler(show_time=False))

__version__ = "0.1.0"
