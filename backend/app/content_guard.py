"""Reject known file links and non-HTML main documents before classification."""

import json
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .normalize import UrlError

FILE_EXTENSIONS = frozenset(json.loads(Path(__file__).with_name("file_types.json").read_text()))
HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
FILE_MESSAGE = "Phisang scans webpages, not files. Enter a webpage URL instead."


class UnsupportedContent(UrlError):
    def __init__(self):
        super().__init__("unsupported_content", FILE_MESSAGE)


def check_page_url(url: str) -> None:
    path = unquote(urlsplit(url).path).rstrip("/")
    filename = path.rsplit("/", 1)[-1].split(";", 1)[0].lower()
    if "." in filename and filename.rsplit(".", 1)[-1] in FILE_EXTENSIONS:
        raise UnsupportedContent()


def check_page_headers(headers: dict) -> None:
    headers = {key.lower(): value for key, value in headers.items()}
    disposition = headers.get("content-disposition", "").split(";", 1)[0].strip().lower()
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if disposition == "attachment" or content_type not in HTML_TYPES:
        raise UnsupportedContent()
