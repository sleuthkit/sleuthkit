# NAND preprocessing device profiles

One JSON file per observed device/layout. Initial profile:
`qualcomm-kommbox-4352.json`, from Gerd1986/qnxprobe's `ftl` branch at
dfa12f2231ef5900ade8fb61aefd6166357ebdcc, `qualcomm_kombox.py`.
This is an observed Kommbox configuration, not a universal Qualcomm preset.

Profiles contain data only; no Python code or commands are executed from JSON.
Use an explicit profile ID/path. There is no automatic device identification.

Schema version 1:

* `id`, `description`, `notes`: identity and evidence/limitations.
* `physical_page_bytes`, `logical_page_bytes`: transport/input and output size.
* `ecc`: `algorithm: bch`, field `m`, correction capacity `t`, primitive
  polynomial as a hex string and `bit_order: msb-first`.
* `operations`: ordered output operations. Each has `kind: bch` or `copy`
  and an ordered `data_ranges` array of `[physical_page_offset, length]`.
  BCH operations also have `ecc_range: [offset, length]`.

Output concatenates the data ranges, in operation order. Bytes in no data/ECC
range are discarded: stuff, pad and spare bytes are thus described by the gaps.
Ranges must not overlap; their total emitted length must equal the logical page
size. ECC parity length must fit the BCH generator degree. Only byte-aligned
parity and systematic MSB-first shortened binary BCH are supported. No LSB-first,
inverted/XOR parity, scrambling, Reed-Solomon or parity padding is guessed.

For the Kommbox profile, seven operations emit 516 bytes each and use 13-byte
parity. A final copy operation emits 484 bytes without known BCH coverage.
This emits 4096 bytes from a 4352-byte page and discards eight stuff bytes,
fourteen pad bytes and 143 spare bytes. All-FF data/parity is treated as erased.

Create additional files here (or in your own directory supplied with
`--profiles-dir`). This repository's generic `config/` directory is ignored for
autotools output; add intentional profile files with `git add -f config/flash_devices/NAME.json`.
For a new device, document how geometry, ECC orientation and coverage were
verified, and supply an independent parity/corruption fixture. Do not apply a
similar-looking profile merely because the SoC vendor matches.
