"""The include markers of README.md, which other documentation reads sections by.

tests/readme_includes.py holds the rules a block between the markers keeps. Each test below
holds README.md to one of them, and the last two show that each rule refuses a block that breaks
it and accepts one that only resembles a break.
"""

from __future__ import annotations

import pytest
import readme_includes


def test_markers_pair_up() -> None:
    assert readme_includes.blocks(), "README.md has no include markers, so these tests would check nothing"
    assert readme_includes.pairing() == []


def test_names_are_well_formed_and_unique() -> None:
    assert readme_includes.names() == []


def test_each_block_opens_a_section() -> None:
    assert readme_includes.placement() == []


def test_each_block_holds_text_within_one_section() -> None:
    assert readme_includes.sections() == []


def test_each_block_closes_its_code_fences() -> None:
    assert readme_includes.fences() == []


def test_no_block_links_to_an_anchor() -> None:
    assert readme_includes.anchor_links() == []


def test_no_block_names_its_own_page() -> None:
    assert readme_includes.self_reference() == []


def test_no_block_refers_to_a_section_by_name() -> None:
    assert readme_includes.section_references() == []


def _readme(*body: str, heading: str = "## Section", name: str = "a-block") -> list[str]:
    """A README with one block named `name` under `heading`, holding `body`."""
    return [heading, "", f"<!-- lq-include: {name} -->", *body, f"<!-- lq-include-end: {name} -->"]


@pytest.mark.parametrize(
    ("check", "lines"),
    [
        ("pairing", _readme("text")[:-1]),
        ("pairing", ["## Section", "", "<!-- lq-include:a-block -->", "text"]),
        ("pairing", _readme("<!-- lq-include: inner -->", "text", "<!-- lq-include-end: inner -->")),
        ("names", _readme("text", name="A_Block")),
        ("names", _readme("text") + _readme("text")),
        ("placement", _readme("text", heading="### Section")),
        ("placement", ["## Section", "<!-- lq-include: a-block -->", "text", "<!-- lq-include-end: a-block -->"]),
        ("sections", _readme()),
        ("sections", _readme("text", "## Another section", "text")),
        ("sections", _readme("text", "", "   # Another section")),
        ("sections", _readme("text", "", " ##")),
        ("sections", _readme("text", "", "Another section", "===")),
        ("sections", _readme("text", "", "Another section", "  ---  ")),
        ("fences", _readme("```bash", "command")),
        ("anchor_links", _readme("See [Install](#install).")),
        ("anchor_links", _readme("See [Install][install].") + ["", "[install]: #install"]),
        ("anchor_links", _readme("See [Install][].") + ["", "[install]: #install"]),
        ("anchor_links", _readme("See [Install].") + ["", "[Install]: <#install>"]),
        ("anchor_links", _readme("See [the steps][install].", "", "[install]: #install")),
        ("anchor_links", _readme('See <a href="#install">Install</a>.')),
        ("anchor_links", _readme("See <a href='#install'>Install</a>.")),
        ("anchor_links", _readme("See <a HREF=#install>Install</a>.")),
        ("self_reference", _readme("As this README says.")),
        ("self_reference", _readme("It installs from a checkout of this repository.")),
        ("section_references", _readme('A bad instant (see "Validator scope").')),
        ("section_references", _readme('Read "Use from Python" below.')),
    ],
)
def test_each_rule_refuses_a_block_that_breaks_it(check: str, lines: list[str]) -> None:
    assert getattr(readme_includes, check)(lines)


@pytest.mark.parametrize(
    ("check", "lines"),
    [
        ("sections", _readme("text", "", "### A subsection", "text")),
        ("sections", _readme("text", "", "    # indented code")),
        ("sections", _readme("text", "", "---", "", "text")),
        ("sections", _readme("- an item", "---")),
        ("sections", _readme("```text", "Not a heading", "===", "```")),
        ("anchor_links", _readme("See [the guide][guide].") + ["", "[guide]: https://example.org/guide"]),
        ("anchor_links", _readme("See [the guide](https://example.org/guide#part).")),
        ("anchor_links", _readme("Run `[ -f x ]` first.")),
        ("anchor_links", _readme("```html", '<a href="#x">x</a>', "```")),
    ],
)
def test_each_rule_accepts_what_only_resembles_a_break(check: str, lines: list[str]) -> None:
    assert getattr(readme_includes, check)(lines) == []
