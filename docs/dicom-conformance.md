# DICOM Conformance Statement — De-identification Export

## Scope

- Product: medical-privacy-guard, `dicom-deidentify` command
  (single file, or a directory tree under one shared UID map).
- The input file is never modified. The output is a new file that
  carries `PatientIdentityRemoved = YES`, a `DeidentificationMethod`
  description, and the method code sequence listed below.

## Basis

Dispositions follow the **Basic Application Level Confidentiality
Profile** of DICOM PS3.15 Annex E, Table E.1-1, as implemented by the
project's disposition table, version **`ps315-basic-v3`**. The table
was verified mechanically: every one of the 621 rows of Table E.1-1
was probed against the implementation's observed behaviour, and the
gaps that pass found are closed in v3. Reports and audit events cite
the table version, so a disposition change is always a version bump,
never a silent edit.

Method codes placed in the output:

| Code | Meaning | When |
| --- | --- | --- |
| 113100 | Basic Application Confidentiality Profile | always |
| 113105 | Clean Descriptors Option | always |
| 113104 | Clean Structured Content Option | always |
| 113107 | Retain Longitudinal Temporal Information, Modified Dates | only with `--date-shift-days` |
| 113109 | Retain Device Identity Option | only with `--retain-device` |

## Defaults and operator options

| Aspect | Default | Option |
| --- | --- | --- |
| Dates and times | emptied | shifted consistently with `--date-shift-days` (times of day are emptied unless dates are shifted) |
| Burned-in annotation (`BurnedInAnnotation = YES`) | export refused | `--allow-burned-in` exports anyway; the report keeps pixel risk UNKNOWN |
| Encapsulated documents | export refused | none |
| Private tags | removed | `--retain-private` |
| Patient characteristics (sex, age, and related fields) | removed | `--retain-characteristics` |
| Device information | removed | `--retain-device` |
| PatientName | emptied, never replaced with a dummy name | none |
| Overlay (60xx) and curve (50xx) groups | removed | none |

UIDs are remapped as salted SHA-256 digests under the `2.25` root
(total length ≤ 64). Standard DICOM UIDs (prefix `1.2.840.10008`)
are never remapped. One map covers a whole run — a single file or a
tree — so references between files stay consistent. The salt is
random per run unless `--salt` is given; no mapping table is written
to disk.

Free-text descriptors are cleaned by the guard's own text detectors
under the strictest recipient/purpose pairing. The cleaned value is
then probed again; any residual detection empties the element rather
than letting it pass.

## Self-checks

An output is withheld — nothing is written — when either check fails:

1. In memory: no original value collected during processing may
   survive in the result under its tag.
2. On disk: the written file is re-inspected before it is moved into
   place; if private tags remain that the options promised to
   remove, the temporary file is deleted and the run fails.

## Deviations from the Basic Profile

Declared, not silent:

1. Descriptors take the Clean Descriptors action (clean) where the
   Basic Profile removes them.
2. Dates are emptied by default; the Basic Profile mixes removal
   and emptying per element.
3. Physician and operator names are removed where the Basic Profile
   empties them (stricter). PatientName is emptied, as in Basic.
4. ProtocolName is removed (Basic action), not cleaned.
5. Graphic Annotation Sequence text is cleaned recursively rather
   than replaced with a dummy value.
6. Referenced and source image sequences are processed recursively
   with UID remapping, between the Profile's remove/empty/remap
   alternatives.
7. Elements whose Basic action is a dummy-value replacement are
   emptied instead; this project does not invent replacement values.
8. Manufacturer's Device Class UID is remapped (its Basic action
   is U).

Elements not listed in Table E.1-1 fall back to a rule by value
representation and keyword: name-like text is removed, description-
and comment-like text is cleaned, UID values are remapped, and the
rest is kept.

## What this does not claim

- **Pixel data is not processed.** Pixel annotation risk remains
  UNKNOWN in every report. Metadata de-identification is not a
  release clearance.
- This is not a claim of anonymisation under any legal standard,
  and not a HIPAA Safe Harbor or expert-certification statement.
  Whether a de-identified file may be shared is a decision for the
  data controller, with this statement as one input.
- Compressed transfer syntaxes pass pixel bytes through unchanged;
  this has been verified for JPEG 2000 lossless. Other compressed
  syntaxes have not been separately verified.
- Free-text cleaning is detector-based. The residual-detection check
  empties what it catches; it cannot prove that no identifier
  remains in narrative text.
