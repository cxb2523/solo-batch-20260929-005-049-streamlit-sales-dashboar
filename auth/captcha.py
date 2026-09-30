"""Image captcha, stateless: the answer travels signed inside the token.

The auth package never imports a web framework; app.py renders the SVG
straight into the login page. Wrong captcha and wrong password produce the
same external message at the service boundary.
"""
from __future__ import annotations

import base64
import hmac
import random
import string

from .session import _load_or_create_secret

_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _sign(answer: str) -> str:
    digest = hmac.new(_load_or_create_secret(), answer.encode(), "sha256").digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def new_challenge(rng: random.Random | None = None) -> dict:
    rng = rng or random
    answer = "".join(rng.choice(_ALPHABET) for _ in range(4))
    token = answer + "." + _sign(answer)
    return {"answer": answer, "token": token, "svg": render_svg(answer, rng)}


def verify_answer(token: str | None, guess: str | None) -> bool:
    if not token or "." not in token or not guess:
        return False
    answer, _, sig = token.partition(".")
    if len(answer) != 4:
        return False
    expected = _sign(answer)
    normalised = guess.strip().upper().replace("0", "O").replace("1", "I")
    return hmac.compare_digest(sig, expected) and hmac.compare_digest(answer, normalised)


def render_svg(text: str, rng: random.Random | None = None) -> str:
    rng = rng or random
    width, height = 150, 52
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<rect width="100%" height="100%" fill="#0e1726"/>',
    ]
    for _ in range(24):
        x1, y1 = rng.randint(0, width), rng.randint(0, height)
        x2, y2 = rng.randint(0, width), rng.randint(0, height)
        color = rng.choice(["#2a9d8f", "#e76f51", "#e9c46a", "#8ab17d"])
        parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="1" opacity="0.6"/>')
    for i, char in enumerate(text):
        x = 18 + i * 32 + rng.randint(-3, 3)
        y = 34 + rng.randint(-4, 4)
        angle = rng.randint(-20, 20)
        color = rng.choice(["#f4a261", "#a8dadc", "#ffd166", "#f1faee"])
        parts.append(
            f'<text x="{x}" y="{y}" font-family="monospace" font-size="26" '
            f'font-weight="bold" fill="{color}" transform="rotate({angle} {x} {y})">{char}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)
