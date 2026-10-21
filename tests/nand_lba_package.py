#!/usr/bin/env python3
"""Package an already validated synthetic fixture with standalone tooling."""
import argparse
import hashlib
from pathlib import Path
import zipfile
ROOT = Path(__file__).resolve().parents[1]
README = '''Synthetisches NAND-Testpaket: LBA-Mapping + BCH-ECC + FAT32

Der Dump ist absichtlich physisch umsortiert und enthält Stuff-Bytes,
ECC-Bitfehler, zwei ältere Page-Duplikate und zwei gelöschte/erased Pages.
Er lässt sich erst nach ECC-Korrektur und LBA-Mapping als FAT32 auswerten.
Keine echten Fahrzeugdaten. Die Config gilt nur für dieses synthetische Layout.

Mit Python 3 (keine zusätzlichen Python-Pakete):

python tools/flash/preprocess_ubi.py synthetic-nand-ftl-ecc-fat32.bin --profile synthetic-lba-bch-fat32.json --output mein-fat32.img

Danach mein-fat32.img in Autopsy als Disk Image hinzufügen, ohne NAND-Config.
Die bisherige Autopsy-Version enthält dieses neue Mapping-Modul noch nicht.
Alternativ sofort das bereits rekonstruierte reconstructed-fat32.img öffnen.

Sleuthkit prüfen:
fsstat mein-fat32.img
fls -r -p mein-fat32.img

Erwartet: FAT32, HELLO.TXT und PAYLOAD.BIN. Referenz: expected-fat32.img.
Die Image-SHA256 muss expected.json/reference_sha256 entsprechen.
Erwartete Korrekturen: 6 Bits in 3 Codewörtern; 2 Duplikate; 2 erased Pages.
Der .report.json enthält die gesamte physische/logische Zuordnung einschließlich
verworfener Duplikate. Vollständige Feldbeschreibung: docs/NAND_LBA_MAPPING.md.
SHA256SUMS.txt enthält die Prüfsummen aller Paketdateien.

Config-Geometrie: 4224 physische Bytes -> 4112 korrigierte Bytes
(4096 Nutzdaten + 16 geschützte Metadaten) -> 4096 logische Bytes.
Die letzten 16 Bytes werden beim Mapping entfernt, nicht vor der ECC-Korrektur.
Das erzeugte FAT32-Image ist 34 MiB groß.

Reproduzieren: python tests/nand_lba_fixture.py neuer-test
Tests: python tests/nand_lba_regression.py --fixture neuer-test
Optional: --tools PFAD_ZU_SLEUTHKIT_BIN für fsstat/fls/icat-Inhaltsprüfung.
'''


def package(fixture, output):
    fixture, output = Path(fixture), Path(output)
    entries = {'README.txt': README.encode(),
               'RUN_TEST.cmd': b'@echo off\r\npy -3 tools\\flash\\preprocess_ubi.py synthetic-nand-ftl-ecc-fat32.bin --profile synthetic-lba-bch-fat32.json --output mein-fat32.img\r\nif errorlevel 1 exit /b 1\r\npause\r\n'}
    for name in ('synthetic-nand-ftl-ecc-fat32.bin', 'synthetic-lba-bch-fat32.json',
                 'expected-fat32.img', 'reconstructed-fat32.img',
                 'reconstructed-fat32.img.report.json', 'expected.json', 'fsstat.txt', 'fls.txt'):
        path = fixture/name
        if path.is_file(): entries[name] = path.read_bytes()
    for name in ('tools/flash/preprocess_ubi.py', 'tools/flash/nand_lba.py', 'tools/flash/bch.py',
                 'tools/flash/LICENSE.txt', 'tests/nand_lba_fixture.py', 'tests/nand_lba_regression.py',
                 'tests/flash_preprocess_regression.py', 'docs/NAND_LBA_MAPPING.md'):
        entries[name] = (ROOT/name).read_bytes()
    entries['SHA256SUMS.txt'] = ''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n'
                                       for name, data in sorted(entries.items())).encode()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 15, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=9)
    print(str(output.resolve()), output.stat().st_size, flush=True)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('fixture', type=Path)
    ap.add_argument('output', type=Path)
    args = ap.parse_args(); package(args.fixture, args.output)
