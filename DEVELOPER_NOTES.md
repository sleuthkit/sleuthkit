# Developer Notes — Building and Testing on Kali Linux

Local build/test notes for The Sleuth Kit 4.15.0 (`develop-4.1x`), recorded on
Kali GNU/Linux Rolling 2026.3. These supplement `INSTALL.txt`; nothing in the
tracked source tree was modified to get the build and test suite working.

Verified toolchain:

| Component | Version |
|---|---|
| g++ | 16.2.0 (Debian) |
| autoconf | 2.73 |
| automake | 1.18.1 |
| libtool | 2.6.2 |
| OpenJDK | 25.0.4 |
| cppunit | 1.15.1 |
| libewf | 20140816 |
| libbfio | 20170123 |

## Quick start

```bash
sudo apt-get install -y autoconf automake libtool libcppunit-dev libewf-dev
./bootstrap
./configure CPPUNIT_CONFIG="$HOME/.local/bin/cppunit-config"   # see "cppunit detection" below
make -j"$(nproc)"
make -j"$(nproc)" check
```

## Build prerequisites

A bare Kali install has `build-essential` but **not** the autotools. Without
them `./bootstrap` fails immediately with `aclocal: not found`, since bootstrap
is just a thin wrapper around `aclocal`/`libtoolize`/`autoconf`/`automake`.

```bash
sudo apt-get install -y autoconf automake libtool
```

`./bootstrap` then succeeds. It emits obsolete-macro warnings for
`AM_PROG_LIBTOOL`, `AC_HEADER_STDC`, `AC_PROG_GCC_TRADITIONAL`, `AC_LANG_C`,
`AC_TRY_LINK`, and `AC_FD_CC`. These are upstream deprecations that modern
autoconf still accepts; they are harmless and can be ignored.

## Fix: cppunit detection disables the unit tests

**Symptom.** `make check` reports only 2 tests (1 pass, 1 skip) and never
descends into `unit_tests/`, even with `libcppunit-dev` installed. The
generated top-level `Makefile` contains a commented-out assignment:

```make
#UNIT_TESTS = unit_tests
```

**Cause.** `Makefile.am:18` gates the `unit_tests` subdirectory on the
`CPPUNIT` automake conditional, which `configure.ac:23` derives from
`no_cppunit` — set by the legacy `AM_PATH_CPPUNIT` macro in `m4/cppunit.m4`.
That macro locates cppunit exclusively through the `cppunit-config` helper
script, which upstream cppunit **removed in 1.13**; 1.15.1 ships pkg-config
metadata only. Detection therefore fails on any modern distro and the unit
tests are silently dropped from the build.

Note that `configure.ac:191` *does* perform a working pkg-config probe
(`ac_cv_cppunit=yes`, feeding the separate `HAVE_CPPUNIT` conditional), but
`Makefile.am` keys off the stale `CPPUNIT` conditional instead.

**Workaround** (no source changes): provide a `cppunit-config` shim backed by
pkg-config and point configure at it.

```sh
#!/bin/sh
# ~/.local/bin/cppunit-config  (chmod +x)
case "$1" in
    --version) pkg-config --modversion cppunit ;;
    --cflags)  pkg-config --cflags cppunit ;;
    --libs)    pkg-config --libs cppunit ;;
    --prefix)  pkg-config --variable=prefix cppunit ;;
    *)         echo "usage: cppunit-config [--version|--cflags|--libs|--prefix]" >&2; exit 1 ;;
esac
```

```bash
./configure CPPUNIT_CONFIG="$HOME/.local/bin/cppunit-config"
```

Configure now reports `checking for Cppunit - version >= 1.12.1... 1.15.1`, the
Makefile contains `UNIT_TESTS = unit_tests`, and `test_base` builds and runs.

A proper upstream fix would make `Makefile.am` use the pkg-config-derived
`HAVE_CPPUNIT` conditional rather than `CPPUNIT`, or drop `m4/cppunit.m4`
in favour of `PKG_CHECK_MODULES`.

## Known cosmetic defect: the `-lcppunit` link probe

Configure always prints:

```
checking for TestRunner in -lcppunit... no
```

This is a bug in the probe itself, not a missing library. `configure.ac:205`
assigns the cppunit libraries to `LDFLAGS` instead of `LIBS`:

```
CFLAGS="$CPPUNIT_CLFAGS"     # also note the typo: CLFAGS
LDFLAGS="$CPPUNIT_LIBS"
```

`LDFLAGS` is placed *before* the object file on the link line, so GNU ld
discards `-lcppunit` before the undefined `CppUnit::TextTestRunner` symbols are
seen, and the check fails with `undefined reference`. The result
(`ax_cv_cppunit`) is only printed and never consumed, so the failure is
harmless — the unit tests still link and pass.

## Optional dependencies

The default configure run on a clean Kali box disables every optional image
format. Install these *before* configuring if you need them:

| Feature | Package | Effect if absent |
|---|---|---|
| libewf | `libewf-dev` | `.E01` (EnCase) images unreadable |
| libbfio | `libbfio-dev` (pulled in by libewf-dev) | required by libewf |
| AFFLIB | not packaged on Kali | `.aff` images unreadable |
| libvslvm | not packaged on Kali | LVM pools undetected |
| libvhdi / libvmdk | not packaged on Kali | `.vhd` / `.vmdk` images unreadable |

`libewf-dev` is effectively mandatory for the test corpus, since most images
there are `.E01`. Re-run `./configure` after installing; check the summary
block it prints at the end.

## Test data

`make check` alone exercises very little. The public corpus used by CI
(`.github/workflows/build-unix.yml`) provides real images:

```bash
curl -sL -o sleuthkit_test_data.zip \
  https://digitalcorpora.s3.amazonaws.com/corpora/drives/tsk-2024/sleuthkit_test_data.zip
unzip -q sleuthkit_test_data.zip -d "$HOME"
make -C "$HOME/sleuthkit_test_data" unpack    # images ship as nested zips
export SLEUTHKIT_TEST_DATA_DIR="$HOME/sleuthkit_test_data"
```

The download is ~18 MB and expands to ~33 MB. The `unpack` step is easy to
miss: without it the image files referenced by the test scripts do not exist
and tools fail with `No such file or directory`.

## Test results

With the above in place:

| Suite | Result |
|---|---|
| `tests/` (`test_libraries.sh`) | 1 pass, 1 skip, 0 fail |
| `unit_tests/base` (`test_base`, cppunit) | 1 pass |
| Case-UCO JUnit (`org.sleuthkit.caseuco.TestSuite`) | 4 run, 0 failures, 0 errors |
| `test/tools/autotools/test_loaddb.sh` | 3/3 images ingested into SQLite |

A manual sweep of `img_stat` / `mmls` / `pstat` / `fsstat` / `fls` over all 29
corpus images parsed every one at the image, volume, pool, or filesystem layer:
FAT12/16/32, exFAT, NTFS, ext3, ISO9660, HFS+, UFS, APFS pool, GPT with 130
partitions, and extended partitions.

### Expected gaps — not build failures

- **`runtests.sh` always skips (exit 77).** It requires a non-public image set
  at `$HOME/from_brian`. Its own header comment states it "is not currently
  being used anywhere". Skipping is correct.
- **`read_apis`, `fs_fname_apis`, `fs_attrlist_apis` never run.** They are
  declared in `tests/Makefile.am` as `check_PROGRAMS` but deliberately left out
  of `TESTS`, so they compile but are not executed. They need `fat12.dd`,
  `fe_test_1.img`, and `ntfs-comp-1.img`, none of which are in the public
  corpus. To run them manually against what is available:
  `./tests/read_apis <dir-containing-the-images>`.
- **XFS and btrfs images only parse at the image layer.** This branch has no
  XFS or btrfs driver under `tsk/fs/`, so `Cannot determine file system type`
  is the correct response for `xfs/xfs-raw-2GB.E01` and the `btrfs/*.E01`
  images.
- **`fuzzing/lvm_test_issue_3235.E01` reports no filesystem.** It is an LVM
  image and `libvslvm` is unavailable on Kali. This is a crash-regression test
  — the meaningful assertion is that the tools exit cleanly, which they do.

## Build warnings

The build is warning-noisy but error-free. Recurring categories: array-bounds
in `tsk/base/tsk_unicode.c`, unused variables, deprecated-declaration notices,
and Java finalizer deprecations in the bindings. None affect the produced
artifacts.

## Artifacts

- `tsk/.libs/libtsk.so.23.0.1` (soname `libtsk.so.23`) and `tsk/.libs/libtsk.a`
- 29 CLI tools under `tools/` — `fls`, `icat`, `istat`, `fsstat`, `ffind`,
  `blk*`, `jls`, `usnjls`, `mmls`, `mmcat`, `mmstat`, `img_stat`, `img_cat`,
  `pstat`, `hfind`, `sigfind`, `srch_strings`, `tsk_loaddb`, `tsk_recover`,
  `tsk_gettimes`, `tsk_comparedir`, `tsk_imageinfo`
- `bindings/java/dist/sleuthkit-4.15.0.jar` plus the JNI native library
- `case-uco/java/dist/sleuthkit-caseuco-4.15.0.jar`
