# CSV/JSON batch measurements and token consistency

This first dataset scope combines caller-selected CSV/JSON files in one local
batch. It provides consistent tokens for TOKENIZE operations and aggregate
quasi-identifier combination measurements. Measurements inform review; they
never authorize release or claim legal compliance or scientific anonymization.

## Consistent tokens within one batch

```bash
medical-privacy-guard dataset-sanitize first.csv second.json \
  --recipient external_approved --purpose research \
  --output-dir minimized-batch
```

The output directory must be new and is created with mode `0700`. Each released
file and `manifest.json` is owner-only (`0600`). Output filenames are positional
(`001.csv`, `002.json`); the manifest uses source indices rather than copying
possibly identifying source filenames. Inputs and existing output directories
are never overwritten.

Before sanitization, the CLI rejects an audit log that aliases any input,
including symlinks and hardlinks. The audit directory cannot be the output
directory or a child of it: audit creation would otherwise preempt publication.
These checks assume deployment-controlled directories, not hostile directory races.

One in-memory TokenRegistry is shared across the serial batch. The same
detected `(type, value)` pair receives the same token in every file. Different
names receive different tokens even when they occur in separate files. This is
value consistency, not person identity resolution: two people with the same
name cannot be distinguished by that name alone.

Only operations that the selected profile TOKENIZE use that map. MASK, REMOVE,
generalization and date shifting retain their existing semantics. For example,
the strict profile tokenizes names and removes MRNs. The original-value map is
never persisted, returned in the manifest or written to audit. Its scope is one
batch; equal-looking tokens from separate batches are not shared identifiers.

Normal Guard gates apply to each file. A BLOCK, unapproved ASK or failed
verification produces no output for that file. Other verified outputs may
remain in the private directory; there is no fallback copying the withheld
source. The command returns 2 for a block/verification failure, 3 for a withheld
ASK, 0 when every file is releasable, and 4 for configuration/I/O errors.
An output I/O failure may leave private verified files or a partial file; it
does not publish a successful manifest or copy withheld original inputs.
This batch command does not automatically approve records; use the individual
[approval workflow](approval-workflow.md) for disclosures requiring review.

Python callers can use `core.dataset.sanitize_dataset(...)`, or explicitly
inject `Guard(token_registry=TokenRegistry())` for serial calls they manage.
Default Guard calls still create a fresh map per payload. Maps are not shared
across processes or protected for concurrent mutation.

## Combination measurements

```bash
medical-privacy-guard dataset-risk first.csv second.json \
  --quasi-identifier age --quasi-identifier region \
  --min-group-size 3
```

CSV requires a non-empty unique header and rectangular rows. JSON accepts a
single row object or an array of row objects. Duplicate JSON keys, non-finite
numbers, missing selected columns and selected object/array values are rejected.
The selected columns must have compatible meaning across the supplied files.

The report groups rows by the selected combination and gives:

- total rows, distinct groups, smallest/largest group and group-size histogram;
- singleton row count and fraction;
- rows in groups smaller than the chosen threshold, and their fraction.

The default threshold is 2, highlighting singleton combinations. It is an
engineering setting, not a release criterion. `dataset-sanitize` accepts the
same options to include **input** measurements in its manifest; these numbers
do not describe the transformed outputs.

For comparison across CSV and JSON, strings compare literally and JSON scalar
numbers/booleans use their JSON text representation: CSV `40` matches JSON
number `40`, while `040` stays different. JSON null is distinct from an empty
CSV cell or text `null`. There is no implicit trimming, age binning, date parsing
or external-population estimation. Original combinations and row membership are
not serialized; the report includes only column names and aggregate counts.

These measurements use the equivalence-class idea described in
[Sweeney's k-anonymity paper](https://dataprivacylab.org/dataprivacy/projects/kanonymity/kanonymity.pdf).
They count rows, not distinct people: duplicate records or repeated visits can
inflate group size. Column selection may omit important clues, and background
knowledge or additional releases can still identify people. No `safe` or
`anonymous` verdict is produced.

Broader anonymization systems such as [ARX](https://github.com/arx-deidentifier/arx)
provide additional models and transformations. This limited scope reuses the
project's TokenRegistry and standard-library grouping without adding dependencies.
