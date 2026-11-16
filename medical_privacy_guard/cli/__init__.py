"""CLI package for medical-privacy-guard.

The console entry point lives in medical_privacy_guard.cli.main:main. This
package intentionally does NOT re-export it: pre-importing the submodule from
__init__ conflicts with `python -m medical_privacy_guard.cli.main` (runpy finds
the module already in sys.modules).
"""
