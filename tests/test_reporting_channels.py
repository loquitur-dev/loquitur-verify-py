"""The two private reporting channels, named alike in CODE_OF_CONDUCT.md and SECURITY.md.

A conduct report reaches the maintainer through the channels of a security report, so section 5
of CODE_OF_CONDUCT.md and the "Reporting channel" section of SECURITY.md name the same two, in
the same order: GitHub's private vulnerability reporting first, then the mailbox. A change to one
document that the other does not follow fails here.
"""

from __future__ import annotations

import re

from repository import ROOT

PRIVATE_REPORTING = "GitHub's private vulnerability reporting"
MAILBOX = re.compile(r"\*\*([A-Za-z0-9._-]+@[A-Za-z0-9.-]+)\*\*")


def _section(document: str, heading: str) -> str:
    """The text of ``document`` under ``heading``, up to the next heading of its level."""
    lines = (ROOT / document).read_text(encoding="utf-8").splitlines()
    start = lines.index(heading)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[start + 1 : end])


def _channels(text: str) -> tuple[int, int, str]:
    """Where the section names private reporting and its first mailbox, and that mailbox."""
    assert PRIVATE_REPORTING in text
    mailboxes = MAILBOX.findall(text)
    assert mailboxes, "the section names no mailbox"
    return text.index(PRIVATE_REPORTING), text.index(mailboxes[0]), mailboxes[0]


def test_the_conduct_and_security_documents_name_the_same_channels_in_the_same_order() -> None:
    conduct = _channels(_section("CODE_OF_CONDUCT.md", "## 5. Reporting conduct issues"))
    security = _channels(_section("SECURITY.md", "## Reporting channel"))
    for private, mailbox, _ in (conduct, security):
        assert private < mailbox, "private reporting is the first channel, the mailbox the second"
    assert conduct[2] == security[2], (conduct[2], security[2])
