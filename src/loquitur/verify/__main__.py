"""``python -m loquitur.verify`` runs the command line, as the ``loquitur-verify`` script does."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
