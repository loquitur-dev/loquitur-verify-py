"""Verdict narrative renderer.

Composes deterministic narrative output for each audience from an
``OfflineVerificationReport``. There are three audiences: ``technical`` (neutral voice for
engineers), ``compliance`` (assertive voice for a security, audit or compliance officer), and
``executive`` (assertive non-technical voice for board or investor reporting).

# Determinism mandate

The renderer is a pure function of:
- the active reason codes inferred from the verification report
- the verdict status (PASS / REVIEW / FAIL)
- aggregate flags (for example the presence of supersession, the conflict count)

It is invariant against:
- timestamps (no wall-clock in output)
- absolute paths (no machine-dependent strings)
- run order (catalog lookups are sorted)

The same input gives byte-identical output, across runs and machines. This is a
precondition for the golden narrative tests and for offline replay
on any platform.

# No inference at runtime

The renderer is template-based. It reads the static
``loquitur.schemas.reason_codes_catalog`` and composes paragraphs by
deterministic templating. Nothing is generated, predicted or sampled: the
text a verifier emits is a function of the catalog and the report, and of
nothing else. That is what makes the golden narrative tests meaningful and
what lets a reader reproduce the wording from the published vocabulary.

# Graceful degradation

If ``loquitur-schemas`` is not installed (the verifier is intentionally
distributable as a pure-verify tool), ``_try_load_catalog`` returns ``None`` and
the renderer composes its narrative without catalog-derived prose. It still
returns a ``VerdictNarrative`` and the verifier still emits the field: the
degradation is in the richness of the text, not in the shape of the output. No
import error reaches the caller.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .errors import LoquiturVerifyError
from .manifest import STATUS_OFFLINE_FAIL, STATUS_OFFLINE_OK, STATUS_OFFLINE_REVIEW
from .runner import (
    VERDICT_FAIL,
    VERDICT_PASS,
    VERDICT_REVIEW,
    OfflineVerificationReport,
)
from .trust_registry import (
    AUTH_STATUS_AMBIGUOUS_KEY,
    AUTH_STATUS_EXPIRED,
    AUTH_STATUS_ISSUER_NOT_FOUND,
    AUTH_STATUS_KEY_NOT_FOUND,
    AUTH_STATUS_NOT_YET_EFFECTIVE,
    AUTH_STATUS_REVOKED,
    AUTH_STATUS_SCOPE_MISMATCH,
    AUTH_STATUS_SUSPENDED,
    AUTH_STATUS_TRUST_REGISTRY_EXPIRED,
    AUTH_STATUS_TRUST_REGISTRY_NOT_YET_EFFECTIVE,
    AUTH_STATUS_VALID,
    SIG_STATUS_INVALID,
    SIG_STATUS_KEY_MISMATCH,
    SIG_STATUS_MALFORMED,
    SIG_STATUS_UNSUPPORTED,
    SIG_STATUS_UNSUPPORTED_PAYLOAD,
)
from .verdict_grounds import verdict_grounds_violations

# WARN is a registry verdict with no offline status of its own: every deterministic
# check completed and at least one recorded a non-blocking condition. It is not imported
# from runner because the offline verifier never produces it: it arrives on registry
# entries, through ``render_narrative_from_codes``.
VERDICT_WARN = "WARN"


class NarrativeRefusedError(ValueError, LoquiturVerifyError):
    """A narrative the renderer refuses: no catalog code grounds the verdict it would narrate.

    verdict-grounds.md section 7.2: a renderer that derives codes from a verifier's report
    MUST refuse to render a narrative whose verdict it can ground in no catalog code. An
    OFFLINE_REVIEW run whose components each reported cleanly (an undeclared or reserved
    member, an unpinned trust root, no evaluation time) gives no code, and is refused.
    """


def _grounds_or_refuse(active: Sequence[str], catalog: Any) -> list[tuple[str, Any]]:
    """The active codes the catalog defines, with their entries; refused when there are none."""
    grounds: list[tuple[str, Any]] = []
    for code in active:
        try:
            entry = catalog.get(code)
        except Exception:
            # Unknown code: skipped rather than failed, so catalog and vocabulary drift do not
            # crash the verifier; it grounds nothing.
            continue
        grounds.append((code, entry))
    if not grounds:
        raise NarrativeRefusedError(
            "no catalog reason code grounds this verdict; a verdict with no grounds is not narrated "
            "(verdict-grounds.md section 7.2)"
        )
    return grounds


# ---------------------------------------------------------------------------
# Reason code inference from OfflineVerificationReport
# ---------------------------------------------------------------------------
# The verifier produces an OfflineVerificationReport whose semantic content
# is structural (booleans, hash matches, presence flags). The narrative
# renderer needs the canonical reason codes the verdict implies. The mapping
# below is deterministic and exhaustive for the offline-verify path.
#
# Each entry expresses: "if this predicate is true on the report, this reason
# code is active". Predicates are pure functions of the report; ordering
# follows the canonical category order so output composition is stable.


# Authorization outcomes mapped to the reason codes that explain them.
#
# The grouping is by what the reader must DO, not by what the verifier saw. Revoked and
# suspended stay separate because one is a security event for the holder and the other a
# reversible administrative hold. Issuer-not-found and key-not-found share a code because
# from the reader's side both mean "this signer is not on the list you are using".
# The one affirmative code in the table below, named because it is read in three places
# and because what separates it from every other entry is worth stating once: it is the
# only code that tells the reader a check SUCCEEDED.
AFFIRMATIVE_AUTHORIZATION_CODE = "AUTHORIZATION_VERIFIED"

# The report's name for the integrity check (report-contract.md section 3.2).
_CHECK_INTEGRITY = "integrity"

AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS: dict[str | None, str] = {
    AUTH_STATUS_REVOKED: "AUTHORIZATION_ISSUER_KEY_REVOKED",
    AUTH_STATUS_SUSPENDED: "AUTHORIZATION_ISSUER_KEY_SUSPENDED",
    # Split by direction. Merging them would render the two scenarios byte-identically, so a
    # record dated before its signer held authority would read the same as a lapsed credential.
    # The first is a books-and-records concern; the second is usually paperwork.
    AUTH_STATUS_EXPIRED: "AUTHORIZATION_ISSUER_KEY_EXPIRED",
    AUTH_STATUS_NOT_YET_EFFECTIVE: "AUTHORIZATION_ISSUER_KEY_NOT_YET_EFFECTIVE",
    AUTH_STATUS_TRUST_REGISTRY_EXPIRED: "AUTHORIZATION_TRUST_MATERIAL_OUTSIDE_VALIDITY_WINDOW",
    AUTH_STATUS_TRUST_REGISTRY_NOT_YET_EFFECTIVE: "AUTHORIZATION_TRUST_MATERIAL_OUTSIDE_VALIDITY_WINDOW",
    AUTH_STATUS_ISSUER_NOT_FOUND: "AUTHORIZATION_ISSUER_NOT_RECOGNISED",
    AUTH_STATUS_KEY_NOT_FOUND: "AUTHORIZATION_ISSUER_NOT_RECOGNISED",
    AUTH_STATUS_SCOPE_MISMATCH: "AUTHORIZATION_SCOPE_MISMATCH",
    AUTH_STATUS_AMBIGUOUS_KEY: "AUTHORIZATION_TRUST_REGISTRY_AMBIGUOUS_KEY",
    # The accept case. Unmapped, a PASS with full trust material would render
    # byte-identically to a plain integrity pass carrying no trust registry at all, so
    # silence on acceptance would read as "authorization was not evaluated", and acceptance
    # is the only outcome on which a reader affirmatively relies.
    AUTH_STATUS_VALID: AFFIRMATIVE_AUTHORIZATION_CODE,
    # INVALID_REGISTRY_ENTRY / INVALID_TRUST_REGISTRY are malformed input, not a
    # statement about authority; the runner categorizes those separately.
}

# VALID_SIGNATURE is deliberately absent: a valid signature on its own is a statement
# about integrity, not about authority, and the runner categorizes it separately. The
# affirmative authority case IS mapped in the table above: AUTH_STATUS_VALID yields
# AUTHORIZATION_VERIFIED, which a `pass` needs to cite an affirmative ground.
AUTHORIZATION_CODE_BY_SIGNATURE_STATUS: dict[str | None, str] = {
    SIG_STATUS_MALFORMED: "AUTHORIZATION_SIGNATURE_NOT_VERIFIED",
    SIG_STATUS_INVALID: "AUTHORIZATION_SIGNATURE_NOT_VERIFIED",
    SIG_STATUS_KEY_MISMATCH: "AUTHORIZATION_SIGNATURE_NOT_VERIFIED",
    SIG_STATUS_UNSUPPORTED: "AUTHORIZATION_SIGNING_METHOD_UNSUPPORTED",
    SIG_STATUS_UNSUPPORTED_PAYLOAD: "AUTHORIZATION_SIGNING_METHOD_UNSUPPORTED",
}


def infer_active_reason_codes(report: OfflineVerificationReport, *, catalog: Any = None) -> tuple[str, ...]:
    """Return the canonical reason codes implied by the verification report.

    The returned tuple is deterministically ordered: codes in the order given by
    ``_CANONICAL_CATEGORY_ORDER`` (integrity, coverage, freshness, conflict, policy,
    evidence, offline, materiality, valuation_crosscheck, authorization, vocabulary), and
    alphabetically within each category. Codes whose category
    is unknown sort last. The same report always produces the same tuple. The list
    is repeated here for the reader; the tuple is authoritative.

    The inference is structural: it is derived from the boolean checks on the
    report rather than from any reason code list emitted elsewhere. This
    keeps the renderer self-contained for the offline-verify path; reason
    codes emitted elsewhere are rendered by ``render_narrative_from_codes``.
    """
    active: list[str] = []

    # Integrity layer (manifest + envelope)
    manifest = report.manifest
    envelope = report.envelope
    p1 = report.p1

    # Manifest
    if manifest is not None:
        if not manifest.manifest_sha256_ok:
            active.append("INTEGRITY_OFFLINE_MANIFEST_SHA_MISMATCH")
        if not manifest.files_ok:
            active.append("INTEGRITY_OFFLINE_MANIFEST_FILE_MISMATCH")
    else:
        # No manifest result at all: it could not be loaded. The runner
        # records this as manifest_verification_failed, whose message names
        # the cause; "manifest_missing" is that message, never an error code.
        if any(
            err.get("code") == "manifest_verification_failed" and err.get("message") == "manifest_missing"
            for err in report.errors
        ):
            active.append("OFFLINE_MANIFEST_MISSING")

    # P1 (canonical input + receipt hashes)
    if p1 is not None:
        if p1.p1_sha256_ok is False:
            active.append("INTEGRITY_OFFLINE_FAIL")
        if p1.input_hash_ok is False:
            active.append("INTEGRITY_OFFLINE_INPUT_HASH_MISMATCH")
        if not p1.canonical_input_present:
            active.append("OFFLINE_CANONICAL_INPUT_MISSING")
        elif p1.input_hash_ok is None:
            # canonical input present but hash check could not be made
            active.append("OFFLINE_INPUT_HASH_NOT_VERIFIED")

    # Envelope (env1 link + structural)
    if envelope is not None:
        if envelope.envelope_sha256_ok is False:
            active.append("INTEGRITY_OFFLINE_ENVELOPE_SHA_MISMATCH")
        if envelope.links_ok is False:
            active.append("INTEGRITY_OFFLINE_ENVELOPE_LINKS_MISMATCH")

    # Authorization failures must not reach the fallback below as INTEGRITY_OFFLINE_FAIL,
    # whose compliance text says the bundle is not internally consistent and tells the
    # reader to have the issuer regenerate it. For a revoked key both claims are false: the
    # evidence is intact, and regenerating changes nothing because the issuer's authority
    # was withdrawn. The report would hide a probable key compromise behind a wrong
    # remediation.
    #
    # Both statuses are read, not just authorization. An unsupported issuer key_type sets
    # authorization_status to AUTHORIZED_ACTIVE_KEY and reports the failure under
    # signature_status (trust_registry.py, the trust_key_type_supported branch), so an
    # inference keyed on authorization alone would still mis-narrate algorithm confusion.
    #
    # Every authorization code's wording starts from an intact record ("The record is
    # undamaged", "Bundle integrity verified"). Cited for a run whose integrity check was not
    # established (a declared member missing, a layer absent or refused, a link or digest
    # that did not match), it would tell the reader the record is undamaged beside the
    # grounds that say it is not. So the authorization codes are cited only when the report
    # establishes the integrity check (report-contract.md section 3.2); otherwise the
    # integrity grounds, or the fallback below, explain the run.
    trust = report.trust_registry
    if trust is not None and _CHECK_INTEGRITY in report.checks_established:
        code = AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS.get(trust.authorization_status)
        # The affirmative code's executive text ends "Both checks passed." On a rejected run
        # that sentence would land last before the closing, the position a skim-reader
        # weights most, and tell the board that both checks passed for a bundle whose
        # registry entry signature did not verify. An affirmative ground may be cited only on
        # a run that actually reached OFFLINE_OK. Dropping it here also keeps the "no specific
        # code" fallback below reachable: a FAIL whose only inferred code was the affirmative
        # one would render a rejection that named no grounds at all.
        if code == AFFIRMATIVE_AUTHORIZATION_CODE and report.status != STATUS_OFFLINE_OK:
            code = None
        if code is not None:
            active.append(code)
        signature_code = AUTHORIZATION_CODE_BY_SIGNATURE_STATUS.get(trust.signature_status)
        if signature_code is not None:
            active.append(signature_code)

    # Aggregate offline failure / review markers (only if no specific code). The integrity
    # fallback says the bundle is not internally consistent and should be regenerated, so it is
    # cited only for a run whose integrity check was not established. A failed run whose
    # integrity check holds (a link that does not hold, a committed FAIL verdict, a trust
    # registry refused as malformed) is no integrity failure (reason-codes.md section 9); with
    # no other code it grounds nothing, and the renderer refuses it (verdict-grounds.md
    # section 7.2).
    if report.status == STATUS_OFFLINE_FAIL and not active and _CHECK_INTEGRITY not in report.checks_established:
        active.append("INTEGRITY_OFFLINE_FAIL")
    if report.status == STATUS_OFFLINE_OK and not active:
        active.append("INTEGRITY_OK")

    # Deduplicate while preserving order, then sort by canonical category.
    return _canonical_order(_dedupe_preserve(active), catalog)


def _dedupe_preserve(codes: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for code in codes:
        if code not in seen:
            seen.add(code)
            out.append(code)
    return out


# Canonical category order: the order in which paragraphs appear in the composed narrative.
# A change to this constant changes the golden narratives, which are regenerated with it.
_CANONICAL_CATEGORY_ORDER: tuple[str, ...] = (
    "integrity",
    "coverage",
    "freshness",
    "conflict",
    "policy",
    "evidence",
    "offline",
    "materiality",
    "valuation_crosscheck",
    "authorization",
    "vocabulary",
)


def _canonical_order(codes: Sequence[str], catalog: Any = None) -> tuple[str, ...]:
    """Sort codes by (canonical category index, code string).

    The caller's catalog is used when it supplies one. Re-loading the ambient one here
    would take paragraph TEXT from the injected catalog and paragraph ORDER from whatever
    happens to be installed, or, with nothing installed, from the alphabetical
    fallback. "Same input -> byte-identical output" cannot hold if ordering depends on
    an import the caller already overrode.
    """
    catalog = catalog if catalog is not None else _try_load_catalog()
    if catalog is None:
        # No catalog available: alphabetical order only.
        return tuple(sorted(codes))

    def _key(code: str) -> tuple[int, str]:
        try:
            entry = catalog.get(code)
            return (_CANONICAL_CATEGORY_ORDER.index(entry.category), code)
        except Exception:
            # An unknown code sorts last, in alphabetical order.
            return (len(_CANONICAL_CATEGORY_ORDER) + 1, code)

    return tuple(sorted(codes, key=_key))


# ---------------------------------------------------------------------------
# Catalog loading (lazy, graceful)
# ---------------------------------------------------------------------------
def _try_load_catalog() -> Any:
    """Return the loaded catalog, or ``None`` if unavailable.

    The verify package is distributable without ``loquitur-schemas`` as a
    dependency; in that distribution mode the narrative renderer declines
    to render. No exception escapes this function.
    """
    try:
        from loquitur.schemas import load_reason_codes_catalog

        return load_reason_codes_catalog()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VerdictNarrative:
    """Audience-specific narrative composition for a verdict.

    All three audience fields are optional so a partial install (verify
    without schemas) returns ``VerdictNarrative(...)`` with everything
    ``None`` rather than raising.
    """

    technical: str | None = None
    compliance: str | None = None
    executive: str | None = None
    # Why no audience was rendered when the renderer refused (NarrativeRefusedError); None
    # otherwise, and then absent from to_dict.
    refused: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "technical": self.technical,
            "compliance": self.compliance,
            "executive": self.executive,
        }
        if self.refused is not None:
            out["refused"] = self.refused
        return out

    @property
    def is_empty(self) -> bool:
        return self.technical is None and self.compliance is None and self.executive is None


# ---------------------------------------------------------------------------
# Catalog-owned composition templates
# ---------------------------------------------------------------------------
def _verdict_template_key(status: str, verdict: str | None) -> str:
    """Return the catalog template key for a status/verdict pair.

    WARN is keyed on the verdict alone because it has no offline status of its own:
    ``_status_from_verdict`` parks it on OFFLINE_REVIEW, so the equality test below would
    fail for a verdict the protocol lists as standard.

    Everything else that does not agree is narrated as FAIL. The catalog carries exactly
    PASS / WARN / REVIEW / FAIL, and an outcome this module cannot classify, including
    the INTERNAL_ERROR status runner.py builds, is not one a reader may rely on, and
    FAIL is the only lead that says so.
    """
    if verdict == VERDICT_WARN:
        return "WARN"
    if status == STATUS_OFFLINE_OK and verdict == VERDICT_PASS:
        return "PASS"
    if status == STATUS_OFFLINE_REVIEW and verdict == VERDICT_REVIEW:
        return "REVIEW"
    return "FAIL"


# Codes for which the FAIL_AUTHORIZATION closing is true, that is, where the record
# itself is sound and only the signer's authority is in question.
#
# AUTHORIZATION_SIGNATURE_NOT_VERIFIED is deliberately excluded. Its own narrative says
# to treat the entry as possible tampering and preserve it, so closing with "the record
# itself is sound" would contradict the paragraph above it: when a signature does not
# verify, the signed statement IS the problem. It falls to the generic FAIL closing,
# whose "require re-issued evidence" is the correct instruction there.
SIGNATURE_FAILURE_CODE = "AUTHORIZATION_SIGNATURE_NOT_VERIFIED"

AUTHORIZATION_REASON_CODES: frozenset[str] = frozenset(
    list(AUTHORIZATION_CODE_BY_AUTHORIZATION_STATUS.values()) + list(AUTHORIZATION_CODE_BY_SIGNATURE_STATUS.values())
) - {SIGNATURE_FAILURE_CODE, AFFIRMATIVE_AUTHORIZATION_CODE}


def _closing_template_key(
    status: str,
    actionable_count: int,
    codes: Sequence[str] = (),
    *,
    verdict: str | None = "",
) -> str:
    """Return the catalog closing-template key for a status/action count.

    The generic FAIL closings prescribe "regenerate and resubmit". For an
    authorization failure that contradicts the paragraph immediately above it, which
    says the evidence is intact and that a regenerated bundle changes nothing.

    The verdict is read for the same reason ``_verdict_template_key`` reads it, and the
    two agree by construction. WARN is parked on OFFLINE_REVIEW upstream, so keying the
    closing on the status alone would put "cannot be confirmed PASS at the offline layer"
    under a lead saying the record is valid and may be relied upon. A status and a verdict
    that do not agree fall to the FAIL closings, never to PASS or REVIEW.
    """
    if verdict == VERDICT_WARN:
        return "WARN"
    if status == STATUS_OFFLINE_OK and verdict == VERDICT_PASS:
        return "PASS"
    if status == STATUS_OFFLINE_REVIEW and verdict == VERDICT_REVIEW:
        return "REVIEW"
    # Only when EVERY active code is an authorization finding. A bundle that fails both
    # integrity and authorization is a defective bundle, and the generic closing is right.
    # A failed signature gets its own closing. The generic FAIL text, "require the issuer
    # to address the failing condition and resubmit", would contradict the paragraph above
    # it, which tells the reader to preserve the artifact for investigation.
    if codes and SIGNATURE_FAILURE_CODE in codes:
        return "FAIL_SIGNATURE"
    if codes and all(code in AUTHORIZATION_REASON_CODES for code in codes):
        return "FAIL_AUTHORIZATION"
    if actionable_count <= 1:
        return "FAIL_SINGLE"
    return "FAIL_MULTI"


def _catalog_template(
    catalog: Any,
    audience: str,
    context: str,
    section: str,
    key: str,
    *,
    status: str,
    verdict: str | None,
) -> str:
    """Render a catalog-owned composition template.

    The reason-code catalog is the SSOT for audience-specific
    narrative wording. The verifier may infer active reason codes and choose
    which template key applies, but it must not own the business wording.
    """
    template = catalog.template(audience, context, section, key)
    rendered: str = template.format(status=status, verdict=verdict)
    return rendered


def _verdict_lead(
    catalog: Any,
    audience: str,
    status: str,
    verdict: str | None,
    *,
    context: str = "offline_verification",
) -> str:
    return _catalog_template(
        catalog,
        audience,
        context,
        "lead",
        _verdict_template_key(status, verdict),
        status=status,
        verdict=verdict,
    )


def _closing(
    catalog: Any,
    audience: str,
    status: str,
    actionable_count: int,
    codes: Sequence[str] = (),
    *,
    verdict: str | None,
) -> str:
    return _catalog_template(
        catalog,
        audience,
        "common",
        "closing",
        _closing_template_key(status, actionable_count, codes, verdict=verdict),
        status=status,
        verdict=verdict,
    )


# ---------------------------------------------------------------------------
# Technical audience composition
# ---------------------------------------------------------------------------
def _technical_paragraph_for_code(catalog_entry: Any) -> str:
    """Compose a single technical paragraph from a catalog entry."""
    return f"{catalog_entry.technical.headline} {catalog_entry.technical.detail}"


# ---------------------------------------------------------------------------
# Verdict-status helpers (independent of OfflineVerificationReport)
# ---------------------------------------------------------------------------
def _status_from_verdict(verdict: str) -> str:
    """Map a public verdict (PASS/REVIEW/FAIL/WARN) to an offline status code.

    Used when composing narratives from inputs that don't carry an offline
    status directly (for example public registry_entry objects).
    """
    if verdict == VERDICT_PASS:
        return STATUS_OFFLINE_OK
    # WARN has no offline status; OFFLINE_REVIEW is a placeholder that only routes the
    # FAIL/non-FAIL split. Both template selectors key WARN on the verdict before they
    # consult the status, because this value is not the outcome.
    if verdict in (VERDICT_REVIEW, VERDICT_WARN):
        return STATUS_OFFLINE_REVIEW
    if verdict == VERDICT_FAIL:
        return STATUS_OFFLINE_FAIL
    return verdict  # an unknown verdict is kept as written; the lead handles it


def _reject_verdict_not_derived_from_codes(verdict: str, codes: Sequence[str], catalog: Any) -> None:
    """Refuse to narrate an entry whose verdict is not the verdict its reason codes derive.

    One rule for a registry entry wherever it is read (verdict_grounds.py, VG-1 to VG-4), the
    rule the link check applies to the same entry, so this renderer never narrates an entry the
    verification path refuses: a verdict more severe than its codes (FAIL citing only
    INTEGRITY_OK), a code cited twice and a code the catalog does not know are refused as a
    verdict less severe than a cited code is.

    Refusal rather than escalation: quietly rewriting a counterparty's verdict would leave the
    narrative disagreeing with the registry entry it describes, and that disagreement is the
    finding. Severities come from the catalog this narrative is composed from.
    """

    def severity_of(code: str) -> str | None:
        entry = _catalog_entry(catalog, code)
        return getattr(entry, "severity", None) if entry is not None else None

    violations = verdict_grounds_violations(verdict, list(codes), severity_of)
    if violations:
        raise ValueError("; ".join(violation.message for violation in violations))


def _catalog_entry(catalog: Any, code: str) -> Any:
    try:
        return catalog.get(code)
    except Exception:
        return None


def render_narrative_from_codes(
    reason_codes: Sequence[str],
    verdict: str,
    *,
    audiences: Sequence[str] = ("technical", "compliance", "executive"),
    catalog: Any = None,
    verdict_context: str = "offline_verification",
) -> VerdictNarrative:
    """Render a VerdictNarrative directly from a reason codes list + verdict.

    Entry point for consumers other than the verifier (for example a reader of a public
    registry entry). Composes audience-specific narratives without requiring an
    ``OfflineVerificationReport``.

    The reason codes set may carry codes from any category (not only
    integrity-layer offline-verify codes). The renderer looks each up in the
    catalog and composes paragraphs in canonical category order. It refuses
    (ValueError) a verdict that is not the verdict its codes derive, VG-1 to
    VG-4 as loquitur-protocol registry-link.md section 2 applies them: an empty
    or duplicated code list, a code the catalog does not define, a verdict more
    or less severe than its highest-severity code, and a PASS with no info code.

    The ``verdict_context`` parameter selects the verdict-lead wording:

    - ``"offline_verification"`` (default): "Offline verification produced
      a PASS verdict...", used when the input is an OfflineVerificationReport.
    - ``"registry_entry"``: "The registry entry records a PASS verdict...",
      used when the input is a public registry_entry. The receipt has been
      issued and committed; the reader is consuming that commitment, not
      running a verification.

    Returns ``VerdictNarrative()`` empty if catalog unavailable.
    """
    # VG-1 (verdict-grounds.md section 4): reason codes that are not an array are absent, and a
    # renderer refuses them. list() would turn an object into its member names and render it.
    if not isinstance(reason_codes, (list, tuple)):
        raise ValueError(
            f"reason_codes must be an array of reason codes, not {type(reason_codes).__name__}; "
            "a verdict with no grounds is not rendered"
        )
    catalog = catalog if catalog is not None else _try_load_catalog()
    if catalog is None:
        return VerdictNarrative()

    status = _status_from_verdict(verdict)
    _reject_verdict_not_derived_from_codes(verdict, list(reason_codes), catalog)
    ordered_codes = _canonical_order(list(reason_codes), catalog)

    technical = (
        _compose_technical_from_ordered_codes(ordered_codes, status, verdict, catalog, verdict_context)
        if "technical" in audiences
        else None
    )
    compliance = (
        _compose_compliance_from_ordered_codes(ordered_codes, status, verdict, catalog, verdict_context)
        if "compliance" in audiences
        else None
    )
    executive = (
        _compose_executive_from_ordered_codes(ordered_codes, status, verdict, catalog, verdict_context)
        if "executive" in audiences
        else None
    )
    return VerdictNarrative(
        technical=technical,
        compliance=compliance,
        executive=executive,
    )


def _compose_technical_from_ordered_codes(
    codes: Sequence[str],
    status: str,
    verdict: str,
    catalog: Any,
    verdict_context: str = "offline_verification",
) -> str:
    parts = [_verdict_lead(catalog, "technical", status, verdict, context=verdict_context)]
    for code in codes:
        try:
            entry = catalog.get(code)
        except Exception:
            continue
        parts.append(_technical_paragraph_for_code(entry))
    parts.append(_closing(catalog, "technical", status, len(codes), codes, verdict=verdict))
    return "\n\n".join(parts)


def _compose_compliance_from_ordered_codes(
    codes: Sequence[str],
    status: str,
    verdict: str,
    catalog: Any,
    verdict_context: str = "offline_verification",
) -> str:
    parts = [_verdict_lead(catalog, "compliance", status, verdict, context=verdict_context)]
    for code in codes:
        try:
            entry = catalog.get(code)
        except Exception:
            continue
        parts.append(_compliance_paragraph_for_code(entry))
    parts.append(_closing(catalog, "compliance", status, len(codes), codes, verdict=verdict))
    return "\n\n".join(parts)


def _compose_executive_from_ordered_codes(
    codes: Sequence[str],
    status: str,
    verdict: str,
    catalog: Any,
    verdict_context: str = "offline_verification",
) -> str:
    parts = [_verdict_lead(catalog, "executive", status, verdict, context=verdict_context)]
    aggregate = _executive_aggregate_summary(tuple(codes), catalog)
    if aggregate:
        parts.append(aggregate)
    actionable = sum(1 for c in codes if c != "INTEGRITY_OK")
    closing = _closing(catalog, "executive", status, actionable, codes, verdict=verdict)
    if closing:
        parts.append(closing)
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Verdict-report-driven composition
# ---------------------------------------------------------------------------
def render_technical_narrative(
    report: OfflineVerificationReport,
    *,
    catalog: Any = None,
) -> str | None:
    """Render the technical audience narrative for a verification report.

    Returns ``None`` if the catalog is unavailable. Otherwise composes a
    deterministic paragraph block: lead sentence (verdict posture), one
    paragraph per active reason code in canonical category order, closing
    sentence stating remaining action. Raises NarrativeRefusedError when no
    catalog code grounds the verdict (verdict-grounds.md section 7.2).
    """
    catalog = catalog if catalog is not None else _try_load_catalog()
    if catalog is None:
        return None

    active = infer_active_reason_codes(report, catalog=catalog)
    grounds = _grounds_or_refuse(active, catalog)
    parts: list[str] = []

    parts.append(_verdict_lead(catalog, "technical", report.status, report.verdict))

    for _code, entry in grounds:
        parts.append(_technical_paragraph_for_code(entry))

    parts.append(_closing(catalog, "technical", report.status, len(active), active, verdict=report.verdict))

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Compliance audience composition
# ---------------------------------------------------------------------------
def _compliance_paragraph_for_code(catalog_entry: Any) -> str:
    """Compose a compliance paragraph: consequence + required action."""
    return (
        f"{catalog_entry.compliance.headline} "
        f"{catalog_entry.compliance.consequence} "
        f"{catalog_entry.compliance.required_action}"
    )


def render_compliance_narrative(
    report: OfflineVerificationReport,
    *,
    catalog: Any = None,
) -> str | None:
    """Render the compliance audience narrative for a verification report.

    Voice is assertive (must / cannot / do not / require). Composition:
    verdict lead, one paragraph per active reason code (consequence +
    required_action), closing line stating audit-trail action.

    Returns ``None`` if the catalog is unavailable. Raises NarrativeRefusedError
    when no catalog code grounds the verdict (verdict-grounds.md section 7.2).
    """
    catalog = catalog if catalog is not None else _try_load_catalog()
    if catalog is None:
        return None

    active = infer_active_reason_codes(report, catalog=catalog)
    grounds = _grounds_or_refuse(active, catalog)
    parts: list[str] = []

    parts.append(_verdict_lead(catalog, "compliance", report.status, report.verdict))

    for _code, entry in grounds:
        parts.append(_compliance_paragraph_for_code(entry))

    parts.append(_closing(catalog, "compliance", report.status, len(active), active, verdict=report.verdict))

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Executive audience composition
# ---------------------------------------------------------------------------
def _executive_aggregate_summary(
    active: tuple[str, ...],
    catalog: Any,
) -> str:
    """Aggregate executive summary across active reason codes.

    The executive audience receives a compact block, not a paragraph per code.
    The per-code executive summaries are joined into a single block. INTEGRITY_OK is left
    out, so a PASS that cites only INTEGRITY_OK has an empty summary.
    """
    if not active:
        return ""
    summaries: list[str] = []
    for code in active:
        try:
            entry = catalog.get(code)
        except Exception:
            continue
        # The INTEGRITY_OK summary is left out: the verdict lead already covers it.
        if code == "INTEGRITY_OK":
            continue
        summaries.append(entry.executive.summary)
    return " ".join(summaries)


def render_executive_narrative(
    report: OfflineVerificationReport,
    *,
    catalog: Any = None,
) -> str | None:
    """Render the executive audience narrative for a verification report.

    Voice is assertive but stripped of technical jargon. Output is compact:
    a single block of 1-3 sentences (verdict lead, optional aggregated
    per-code summary, optional closing action).

    Returns ``None`` if the catalog is unavailable. Raises NarrativeRefusedError
    when no catalog code grounds the verdict (verdict-grounds.md section 7.2).
    """
    catalog = catalog if catalog is not None else _try_load_catalog()
    if catalog is None:
        return None

    active = infer_active_reason_codes(report, catalog=catalog)
    _grounds_or_refuse(active, catalog)

    parts: list[str] = []
    parts.append(_verdict_lead(catalog, "executive", report.status, report.verdict))

    aggregate = _executive_aggregate_summary(active, catalog)
    if aggregate:
        parts.append(aggregate)

    # The "actionable" codes: every active code except the info-level INTEGRITY_OK.
    actionable = sum(1 for c in active if c != "INTEGRITY_OK")
    closing = _closing(catalog, "executive", report.status, actionable, active, verdict=report.verdict)
    if closing:
        parts.append(closing)

    # Executive output is one block, not multi-paragraph. Single-space joined.
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Public render entrypoint
# ---------------------------------------------------------------------------
def render_verdict_narrative(
    report: OfflineVerificationReport,
    *,
    audiences: Sequence[str] = ("technical",),
) -> VerdictNarrative:
    """Render audience-specific narratives for a verification report.

    All three audiences (technical, compliance, executive) are wired.
    Audience selection determines which fields are populated;
    unselected audience fields remain ``None``. When no catalog code grounds
    the verdict, no audience is rendered and ``refused`` says why
    (verdict-grounds.md section 7.2); the report itself is unchanged.
    """
    catalog = _try_load_catalog()
    if catalog is None:
        return VerdictNarrative()

    try:
        technical = render_technical_narrative(report, catalog=catalog) if "technical" in audiences else None
        compliance = render_compliance_narrative(report, catalog=catalog) if "compliance" in audiences else None
        executive = render_executive_narrative(report, catalog=catalog) if "executive" in audiences else None
    except NarrativeRefusedError as exc:
        return VerdictNarrative(refused=str(exc))

    return VerdictNarrative(
        technical=technical,
        compliance=compliance,
        executive=executive,
    )


def report_dict_with_narrative(
    report: OfflineVerificationReport,
    *,
    audiences: Sequence[str] = ("technical",),
) -> dict[str, Any]:
    """``report.to_dict()`` extended with the audience-specific narrative.

    The narrative section is the verdict explainability layer and is opt-in: ``to_dict()``
    carries no narrative, so the default JSON output of the CLI has one shape whether or not the
    narrative extra is installed. Callers that want narrative output call this function or pass
    the ``--narrative`` CLI flag.

    If ``loquitur-schemas`` is not installed, the narrative section is present but its audience
    fields are ``None`` (graceful degradation).
    """
    base = report.to_dict()
    base["narrative"] = render_verdict_narrative(report, audiences=audiences).to_dict()
    return base


__all__ = [
    "NarrativeRefusedError",
    "VerdictNarrative",
    "VERDICT_WARN",
    "infer_active_reason_codes",
    "render_technical_narrative",
    "render_compliance_narrative",
    "render_executive_narrative",
    "render_verdict_narrative",
    "render_narrative_from_codes",
    "report_dict_with_narrative",
]
