"""Standalone offline verifier package for Loquitur evidence bundles.

The package contains ZIP archive loading, manifest and digest verification, P1 and
canonical-input verification, the local links of the env1 envelope, the optional link check
against a registry entry supplied locally, the optional authorization check of the
registry-entry signature against a trust registry supplied locally,
trust-registry root-signature verification against roots supplied by the caller, and the
command-line output and exit-code contract. It does not validate chain anchors, verify
inclusion proofs or finality, judge legal status, compliance or valuation correctness, or
query any online registry.

The default of root-signature verification looks like absence and is not: the pinned root set
ships empty, so with no root supplied the reported outcome is ``NO_PINNED_TRUST_ROOT``. That
is a computed result rather than a skipped check, and ``--trust-root`` turns it into a
verification against a root obtained out of band.

The package also ships an opt-in verdict narrative renderer
(``loquitur.verify.narrative``) that composes deterministic narrative output for each
audience. Narrative requires ``loquitur-schemas`` to be installed (catalog data); without it,
narrative methods return empty output and the rest of the verifier is unaffected.
"""

__all__ = [
    "__version__",
    "VerdictNarrative",
    "render_verdict_narrative",
    "infer_active_reason_codes",
    "verify_registry_link",
    "verify_registry_entry_trust",
    "verify_path",
    "OfflineVerificationReport",
    "exit_code_for_status",
    "read_trust_root_document",
    "TrustRootError",
    "EvaluationTimeError",
    "DOCUMENT_READ_FAILED",
    "LoquiturVerifyError",
]
from typing import TYPE_CHECKING, Any

from ._version import __version__

# LoquiturVerifyError is the one error base of the package and is read eagerly; the entry points
# __getattr__ loads are named in __all__ and tools/public_api_parity.json lists each of them.
from .errors import LoquiturVerifyError as LoquiturVerifyError

if TYPE_CHECKING:
    from .evaluation_time import EvaluationTimeError as EvaluationTimeError
    from .runner import OfflineVerificationReport as OfflineVerificationReport
    from .runner import exit_code_for_status as exit_code_for_status
    from .runner import verify_path as verify_path
    from .trust_root import DOCUMENT_READ_FAILED as DOCUMENT_READ_FAILED
    from .trust_root import TrustRootError as TrustRootError
    from .trust_root import read_trust_root_document as read_trust_root_document


# Late-binding re-exports so the narrative module's lazy ``loquitur-schemas``
# import does not run at package import time. The documented entry points of the Python API are
# importable from the package and loaded from their module on first use, so importing the package
# reads neither the runner nor the narrative renderer.
def __getattr__(name: str) -> Any:
    if name in ("verify_path", "OfflineVerificationReport", "exit_code_for_status"):
        from . import runner

        return getattr(runner, name)
    if name == "EvaluationTimeError":
        from . import evaluation_time

        return evaluation_time.EvaluationTimeError
    if name in ("TrustRootError", "DOCUMENT_READ_FAILED", "read_trust_root_document"):
        from . import trust_root

        return getattr(trust_root, name)
    if name in ("VerdictNarrative", "render_verdict_narrative", "infer_active_reason_codes"):
        from . import narrative

        return getattr(narrative, name)
    if name == "verify_registry_link":
        from . import registry_link

        return registry_link.verify_registry_link
    if name == "verify_registry_entry_trust":
        from . import trust_registry

        return trust_registry.verify_registry_entry_trust
    raise AttributeError(name)
