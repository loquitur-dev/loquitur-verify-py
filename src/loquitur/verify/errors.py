"""The base class of every exception this package raises on purpose.

``LoquiturVerifyError`` is an additional base of the package's public exception classes, beside
the built-in base each of them has always had (``ValueError``, ``OSError`` or ``Exception``), so a
caller can catch whatever the verifier raises as a class of its own with one ``except`` clause and
code that catches the built-in base keeps working. Evidence that fails verification is a report and
never an exception; these are raised for input the caller supplied that the verifier cannot take
(a malformed trust root, a malformed evaluation time, a document or archive it cannot read). The
module imports nothing, so any module of the package can import it.
"""

from __future__ import annotations


class LoquiturVerifyError(Exception):
    """Base class of the exceptions loquitur.verify raises on purpose."""
