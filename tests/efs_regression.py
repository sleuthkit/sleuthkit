#!/usr/bin/env python3
"""Native EFS integration: real QNX/tar oracle and dual-endian multipart dumps."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import struct
import subprocess
import tarfile
import tempfile


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tools', type=pathlib.Path, required=True)
    ap.add_argument('--reference', type=pathlib.Path, required=True)
    ap.add_argument('--read-probe', type=pathlib.Path)
    opt = ap.parse_args()
    spec = importlib.util.spec_from_file_location('qnxprobe_reference', opt.reference/'qnxprobe.py')
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    fixtures = opt.reference/'tests/fixtures'
    tools = {n: opt.tools/n for n in ('fls', 'icat', 'fsstat', 'blkls', 'ils', 'istat')}

    def run(n, *args):
        return subprocess.check_output([str(tools[n]), *map(str, args)])

    def names(image, *args):
        result = {}
        for line in run('fls', '-r', '-p', *args, image).decode().splitlines():
            m = re.match(r'\S+ (\d+):\t(.*)', line)
            if m:
                result[m[2]] = int(m[1])
        return result

    checks = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        known = json.loads((fixtures/'efs.known.json').read_text())
        for label, endian in (('le', '<'), ('be', '>')):
            raw = gzip.decompress((fixtures/f'efs-{label}.img.gz').read_bytes())
            image = tmp/f'efs-{label}.img'
            image.write_bytes(raw)
            assert b'Partition Count: 2' in run('fsstat', image)
            have = names(image)
            expected_names = set()
            free = {int(l.split('|')[0]) for l in run('blkls', '-l', image).decode().splitlines()[3:]}
            for k, p in enumerate(known['partitions'], 1):
                folder = f'Partition_{k:02}_0x{p["base"]:08x}'
                expected_names.add(folder)
                walker = ref.EfsWalker(io.BytesIO(raw), p['base'], p['size'])
                for path, entry in p['files'].items():
                    fullname = folder+'/'+path
                    expected_names.add(fullname)
                    content = run('icat', image, have[fullname])
                    assert len(content) == entry['size'] and hashlib.sha256(content).hexdigest() == entry['sha256'], fullname
                    checks += 1
                    if opt.read_probe:
                        for offset, length in ((0, 17), (899, 100), (len(content), 8)):
                            if offset > len(content):
                                continue
                            buffered = subprocess.check_output([str(opt.read_probe), str(image), str(have[fullname]), str(offset), str(length)])
                            assert buffered == content[offset:offset+length]
                    stat = run('istat', image, have[fullname]).decode()
                    assert f'Modified: {entry["mtime"]}.' in stat
                    assert f'Mode: {entry["mode"] & 0o7777:o}' in stat
                for path in p['dirs']:
                    expected_names.add(folder+'/'+path)
                for path, entry in p['symlinks'].items():
                    fullname = folder+'/'+path
                    expected_names.add(fullname)
                    assert run('icat', image, have[fullname]) == entry['target'].encode()
                    checks += 1
                # Every known historical file extent is byte-accurately carved;
                # no current file content or header may be called unallocated.
                for entry in p['deleted']:
                    for at, length, _state in entry['extents']:
                        assert set(range(at, at+length)) <= free
                todo = [walker.root]
                while todo:
                    node = todo.pop()
                    for ext in walker._chain(node):
                        at = p['base']+ext['u']*walker.unit_size+ext['off']
                        assert not (set(range(at, at+ext['tsize'])) & free)
                    for _name, child in walker.listdir(node):
                        if child[2] & 0o170000 == 0o040000:
                            todo.append(child)
                        else:
                            for ext in walker._chain(child):
                                at = p['base']+ext['u']*walker.unit_size+ext['off']
                                assert not (set(range(at, at+ext['tsize'])) & free)
                assert not (set(range(p['base']-32, p['base'])) & free)
            assert set(have) == expected_names
            # Offsets and unaligned prefix preserve independent partition namespaces.
            prefix = tmp/'prefix.img'
            prefix.write_bytes(bytes(8192)+raw)
            shifted = names(prefix, '-o', 16)
            assert shifted == have
            odd = tmp/'odd.img'
            odd.write_bytes(bytes(37)+raw)
            oddnames = names(odd)
            assert len(oddnames) == len(have)
            sliced = tmp/'partition.img'
            p = known['partitions'][0]
            sliced.write_bytes(raw[p['base']:p['base']+p['size']])
            assert b'Partition Count: 1' in run('fsstat', sliced)
            assert 'Partition_01_0x00000000/readme.txt' in names(sliced)
            # Resolve directory rewrites and data superseding chains; old names
            # stay outside the live tree and their bytes stay available to carve.
            assert not any('old.log' in n or 'gone.bin' in n for n in have)
            bad = bytearray(raw)
            w = ref.EfsWalker(io.BytesIO(raw), p['base'], p['size'])
            boot = w._get_ext(w.boot['root'])
            off = p['base']+boot['u']*w.unit_size+boot['off']
            struct.pack_into(endian+'HH', bad, off+4, 1, 3)  # children point back to root entry
            broken = tmp/'cycle.img'
            broken.write_bytes(bad)
            result = subprocess.run([str(tools['fsstat']), '-f', 'efs', str(broken)], capture_output=True)
            assert result.returncode > 0
            print(f'efs-{label}: two partition folders, live hashes, history carving and offsets passed', flush=True)
        # Both byte orders in one container, with repeated file names and
        # logical unit numbers, must remain in four isolated partition folders.
        little = gzip.decompress((fixtures/'efs-le.img.gz').read_bytes())
        big = gzip.decompress((fixtures/'efs-be.img.gz').read_bytes())
        combined = tmp/'mixed-endian.img'
        combined.write_bytes(little+big)
        mixednames = names(combined)
        roots = [name for name in mixednames if '/' not in name]
        assert len(roots) == 4 and len(set(mixednames.values())) == len(mixednames)
        assert b'Partition Count: 4' in run('fsstat', combined)
        for name, node in mixednames.items():
            if name.endswith('/only.bin'):
                assert len(run('icat', combined, node)) == 640

        # This is QNX mkefs/devf-ram output; the tar was produced from its
        # mounted tree, independently of both parsers.
        raw = gzip.decompress((fixtures/'efs-qnx.img.gz').read_bytes())
        image = tmp/'efs-qnx.img'
        image.write_bytes(raw)
        have = names(image)
        folder = 'Partition_01_0x00000000'
        expected = {folder}
        with tarfile.open(fixtures/'efs-qnx.tar.gz') as tar:
            for member in tar.getmembers():
                path = member.name.strip('/')
                if not path:
                    continue
                name = folder+'/'+path
                expected.add(name)
                stat = run('istat', image, have[name]).decode()
                assert f'Mode: {member.mode & 0o7777:o}' in stat, name
                assert f'Modified: {int(member.mtime)}.' in stat, name
                if member.isfile():
                    content = tar.extractfile(member).read()
                    assert run('icat', image, have[name]) == content, name
                    checks += 1
                elif member.issym():
                    assert run('icat', image, have[name]) == member.linkname.encode(), name
                    checks += 1
        assert set(have) == expected
        listing = run('ils', '-a', image).decode()
        for node in have.values():
            assert f'\n{node}|a|' in listing
        # Foreign prefix/trailer outside EFS partitions is not exposed as free.
        carved = run('blkls', image)
        assert len(carved) <= ref.efs_partitions(io.BytesIO(raw), len(raw))[0]['size']
        for data in (bytes(4096), b'QSSL_F3S'+bytes(4096), raw[:512]):
            bad = tmp/'invalid.img'
            bad.write_bytes(data)
            result = subprocess.run([str(tools['fsstat']), '-f', 'efs', str(bad)], capture_output=True)
            assert result.returncode > 0
        print(f'{checks} EFS payload checks passed, including real QNX image versus mounted-tree tar', flush=True)
        print('EFS partition folders, metadata, superseding, byte-accurate unallocated and malformed input tests passed')


if __name__ == '__main__':
    main()
