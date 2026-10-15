# UBI/UBIFS NAND preprocessor

`tools/flash/preprocess_ubi.py` is a standalone Python 3.10+ preprocessor;
it uses only the standard library. Output is a clean page-data-only image for
the native UBI/UBIFS reader. It does not translate UBI volumes or modify the
native filesystem parser. Original dumps remain read-only.

```
python tools/flash/preprocess_ubi.py --list-profiles
python tools/flash/preprocess_ubi.py chip.dmp --profile qualcomm-kommbox-4352 -o clean.ubi
fsstat clean.ubi
fls -r -p clean.ubi
```

Use `--profile /path/to/device.json` for an external config, or
`--profiles-dir /path/to/configs --profile DEVICE_ID`. Device configs live in
`config/flash_devices/`. The layout is selected explicitly, never guessed.

The observed Qualcomm Kommbox profile reproduces the qnxprobe `ftl` branch:
4352 input bytes -> 4096 output bytes; first seven BCH codewords each use
372 data + one stuff byte + 144 data + 13 parity + two pad bytes. The final
region contributes 372 + 112 bytes after removing the eighth stuff byte and
143 spare bytes. BCH uses m=13, t=8, primitive polynomial 0x201B, MSB-first.

## Error policy and evidence

* Default: BCH on; abort on an uncorrectable codeword. The output is written
  to a temporary file and committed only after successful processing. An
  existing output is not replaced on a decoding failure, even with `--force`.
* `--uncorrectable keep`: preserve undecodable payload bytes, record their
  physical positions, and mark the report as degraded. This matches the
  reference's recovery behavior but is deliberately opt-in.
* `--ecc off`: perform only geometry cleanup; report codewords as unchecked.
* Erased all-FF payload/parity is copied and counted separately.
* Successful output receives `OUTPUT.report.json`: profile hash, input/output
  SHA256, geometry, corrected-bit/codeword counts, erased/unchecked/uncorrectable
  counts, unprotected bytes and up to 10,000 error positions (omissions counted).
* Original input aliases, incomplete pages, overlapping/out-of-bounds profile
  ranges, wrong parity sizes and unknown schema fields are rejected.

The last 484 output bytes per Kommbox page have no decoded BCH coverage in the
reference and remain **unprotected**. A successful syndrome verification shows
membership in this configured code, not cryptographic authenticity. Correct
recovery is guaranteed only within the code's error capacity and with the correct
device profile; corruption beyond t errors is not always detectable and can
miscorrect. No universal ECC or device compatibility is claimed.

## Release packages

New UBI release builds bundle `flash_preprocessor/preprocess_ubi.py`, `bch.py`,
`profiles/`, documentation and license inside the Windows/Linux packages.
Run `python flash_preprocessor/preprocess_ubi.py ...` from the unpacked package.
Python must be installed separately; the utility is not embedded in the JNI
library or automatically run by Autopsy. The previous v4.15.0-ubi.1 assets are
unchanged; a new release build is required to distribute these additions.

Regression tests use an independent BCH encoder, one through eight mixed
payload/parity bit errors, a chosen beyond-radius failure, erased pages,
atomic-output/error policies, config validation and a full kernel-built UBI
fixture encoded into the physical transport, then reconstructed byte-for-byte
and opened by native fsstat. The user's original Kommbox dump has not been
reprocessed here.
