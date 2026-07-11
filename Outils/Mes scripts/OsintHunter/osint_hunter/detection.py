"""Input type auto-detection."""

import re

from .models import InputType


_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")
_PHONE_RE = re.compile(r"^\+?\d[\d\s\-().]{6,18}\d$")


def detect_input(query: str) -> InputType:
    q = query.strip()

    if _EMAIL_RE.match(q):
        return InputType.EMAIL

    digits = re.sub(r"[\s\-().+]", "", q)
    if _PHONE_RE.match(q) and len(digits) >= 7:
        return InputType.PHONE

    if " " in q and len(q.split()) >= 2:
        return InputType.NAME

    return InputType.USERNAME


def input_icon(it: InputType) -> str:
    return {
        InputType.USERNAME: "\U0001f464",  # bust
        InputType.EMAIL: "\U0001f4e7",     # email
        InputType.NAME: "\U0001f524",      # abc
        InputType.PHONE: "\U0001f4de",     # phone
    }[it]
