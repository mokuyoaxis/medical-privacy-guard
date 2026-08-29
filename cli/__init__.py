"""CLI package for medical-privacy-guard.

The console entry point lives in cli.main:main. This package intentionally
does NOT re-export it: pre-importing the submodule from __init__ conflicts
with `python -m cli.main` (runpy finds the module already in sys.modules).
"""
