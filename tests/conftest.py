"""Shared test configuration.

pydicom backs the DICOM scanner and is an optional extra
(``pip install medical-privacy-guard[dicom]``). Its tests skip, rather than
fail, when the extra is absent -- a missing optional feature is not a broken
one. Point ``DICOM_EXTRA_PATH`` at an extracted wheel to run them without
installing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

extra = os.environ.get("DICOM_EXTRA_PATH")
if extra:
    sys.path.insert(0, str(Path(extra)))

try:
    import pydicom  # noqa: F401

    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False
