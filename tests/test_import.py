from __future__ import annotations

from import_guards import assert_no_new_forbidden_modules_loaded, snapshot_forbidden_modules


def test_public_namespace_import_does_not_load_backend_stack() -> None:
    before = snapshot_forbidden_modules()

    import loquitur.verify as verify

    assert verify.__version__
    assert_no_new_forbidden_modules_loaded(before)
