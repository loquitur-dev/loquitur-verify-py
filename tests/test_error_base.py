"""Every exception the package raises on purpose is also a ``LoquiturVerifyError``.

The base is an additional base: each class keeps the built-in base it had (``ValueError``,
``OSError`` or ``Exception``), so a caller that catches that base is unaffected and a caller that
wants only the verifier's own errors catches one class.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import pytest

import loquitur.verify
from loquitur.verify import LoquiturVerifyError
from loquitur.verify.canonical import CanonicalizationError, JsonLoadError
from loquitur.verify.evaluation_time import EvaluationTimeError
from loquitur.verify.members import BundleMemberError, UnsafeBundleMemberError
from loquitur.verify.secp256k1 import PublicKeyError
from loquitur.verify.trust_root import TrustRootError, parse_trust_roots

# The built-in base each class had before the common base, and keeps.
BUILTIN_BASE = {
    "ArchiveLoadError": Exception,
    "CanonicalizationError": ValueError,
    "EnvelopeVerificationError": Exception,
    "EvaluationTimeError": ValueError,
    "JsonLoadError": ValueError,
    "ManifestVerificationError": Exception,
    "BundleMemberError": OSError,
    "NarrativeRefusedError": ValueError,
    "P1VerificationError": Exception,
    "PublicKeyError": ValueError,
    "RegistryLinkVerificationError": Exception,
    "TrustRegistryVerificationError": Exception,
    "TrustRootError": ValueError,
    "TrustRootDocumentUnreadableError": ValueError,
    "TrustRootDocumentUnsupportedVersion": ValueError,
    "VocabularyError": ValueError,
}


def _exception_classes() -> dict[str, type[BaseException]]:
    """Every public exception class a module of the package defines, by name."""
    found: dict[str, type[BaseException]] = {}
    for info in pkgutil.iter_modules(loquitur.verify.__path__, "loquitur.verify."):
        module = importlib.import_module(info.name)
        for name, value in vars(module).items():
            if (
                inspect.isclass(value)
                and issubclass(value, BaseException)
                and value.__module__ == info.name
                and not name.startswith("_")
            ):
                found[name] = value
    return found


def test_the_base_is_exported_and_is_an_exception() -> None:
    assert issubclass(LoquiturVerifyError, Exception)
    assert LoquiturVerifyError.__module__ == "loquitur.verify.errors"
    assert LoquiturVerifyError.__doc__


def test_every_public_exception_class_of_the_package_is_a_verify_error() -> None:
    classes = _exception_classes()
    classes.pop("LoquiturVerifyError")
    assert set(BUILTIN_BASE) <= set(classes), "an exception class this test does not know"
    for name, cls in classes.items():
        assert issubclass(cls, LoquiturVerifyError), name


@pytest.mark.parametrize(("name", "builtin"), sorted(BUILTIN_BASE.items()))
def test_each_class_keeps_the_built_in_base_it_had(name: str, builtin: type[BaseException]) -> None:
    assert issubclass(_exception_classes()[name], builtin)


def test_one_except_clause_catches_what_the_verifier_raises() -> None:
    with pytest.raises(LoquiturVerifyError):
        parse_trust_roots({"object_type": "trust_root_document", "schema_version": "v1", "roots": "not a list"})
    with pytest.raises(ValueError, match="x"):
        raise TrustRootError("x")
    for error in (
        CanonicalizationError("x"),
        JsonLoadError("x"),
        EvaluationTimeError("x"),
        PublicKeyError("x"),
        UnsafeBundleMemberError("x"),
    ):
        try:
            raise error
        except LoquiturVerifyError as caught:
            assert caught is error


def test_an_os_error_keeps_its_errno_arguments() -> None:
    error = BundleMemberError(2, "gone")
    assert isinstance(error, OSError)
    assert isinstance(error, LoquiturVerifyError)
    assert error.errno == 2
