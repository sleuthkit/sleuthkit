#!/usr/bin/env python3
"""Native ETFS replay against synthetic bytes, QNXProbe and NFI's QNX tar exports."""
import argparse
import importlib.util
import io
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from etfs_fixture import fixture


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--reader-probe',type=Path,required=True)
    ap.add_argument('--reference',type=Path,required=True)
    ap.add_argument('--nfi',type=Path,required=True)
    ap.add_argument('--tools',type=Path)
    ap.add_argument('--read-probe',type=Path)
    opt=ap.parse_args()
    spec=importlib.util.spec_from_file_location('reference',opt.reference/'qnxprobe.py')
    ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
    def probe(image,command,*args):
        return subprocess.check_output([str(opt.reader_probe),str(image),command,*map(str,args)])
    def run(tool,*args):
        return subprocess.check_output([str(opt.tools/tool),*map(str,args)])
    def listing(image):
        nodes={}
        for line in probe(image,'list').decode().splitlines():
            v=line.split('\t',9);nodes[int(v[0])]=[int(x) for x in v[1:9]]+[v[9]]
        def path(id):
            if id==1:return ''
            n=nodes[id];p=path(n[0]);return (p+'/' if p else '')+n[-1]
        return {path(id):(id,n) for id,n in nodes.items()}
    def cli_names(image,*extra):
        out={}
        for line in run('fls','-r','-p',*extra,image).decode().splitlines():
            m=re.match(r'\S+ (\d+):\t(.*)',line)
            if m:out[m[2]]=int(m[1])
        return out
    count=0
    with tempfile.TemporaryDirectory() as tmp:
        tmp=Path(tmp)
        for page in (512,1024,2048,4096,8192,16384):
            # Extend the fixture table to a complete page at larger geometries.
            raw,expected=fixture(page)
            image=tmp/'etfs.img';image.write_bytes(raw)
            have=listing(image)
            assert 'deleted.txt' not in have
            assert ref.etfs_pagesize(io.BytesIO(raw),0,len(raw))==page
            walker=ref.EtfsWalker(io.BytesIO(raw),0,len(raw),page)
            for name,data in expected.items():
                id,n=have[name]
                assert probe(image,'read',id)==data,name
                # QNXProbe intentionally has a different synthetic orphan-folder name.
                if name not in ('missing.bin',):
                    assert b''.join(walker.read_file(id-1,len(data)))==data,name
                assert n[2:7]==[123,456,1700000000,1700000001,1700000002]
                count+=1
            assert b'HISTORICAL-ETFS-MARKER' in probe(image,'free')
            assert b'DELETED-ETFS-MARKER' in probe(image,'free')
            if opt.tools:
                assert b'QNX ETFS' in run('fsstat',image)
                assert f'Page Data Size: {page}'.encode() in run('fsstat','-f','etfs',image)
                names=cli_names(image)
                assert names=={p:id for p,(id,n) in have.items() if p}
                for name,data in expected.items():
                    assert run('icat',image,names[name])==data,name
                assert b'HISTORICAL-ETFS-MARKER' in run('blkls',image)
                assert b'DELETED-ETFS-MARKER' in run('blkls',image)
                assert b'UID: 123' in run('istat',image,names['status.txt'])
                assert b'|a|' in run('ils','-a',image)
                offset=tmp/'offset.img';offset.write_bytes(bytes(8192)+raw)
                assert cli_names(offset,'-o',16)==names
                assert run('icat','-o',16,offset,names['status.txt'])==expected['status.txt']
                if opt.read_probe:
                    target='nested/'+next(k.split('/',1)[1] for k in expected if k.startswith('nested/'))
                    for at,length in ((0,17),(page-3,13),(2*page-3,20),(2*page+4,10)):
                        got=subprocess.check_output([str(opt.read_probe),str(image),str(names[target]),str(at),str(length)])
                        assert got==expected[target][at:at+length]
            for broken in (bytes(len(raw)),b'\xff'*len(raw),raw[:-1]):
                bad=tmp/'bad.img';bad.write_bytes(broken)
                assert subprocess.run([str(opt.reader_probe),str(bad),'list'],capture_output=True).returncode!=0
                if opt.tools:assert subprocess.run([str(opt.tools/'fsstat'),'-f','etfs',str(bad)],capture_output=True).returncode!=0
            print(f'ETFS {page}: replay, ties, ECC flag, holes, long names, orphans, deletion and offsets passed',flush=True)
        folder=opt.nfi/'tests/qnx_etfs/test_data'
        for stem in ('test_image','old_test_image'):
            image=folder/(stem+'.bin');have=listing(image)
            raw=image.read_bytes();w=ref.EtfsWalker(io.BytesIO(raw),0,len(raw),1024)
            cli=cli_names(image) if opt.tools else {}
            with tarfile.open(folder/(stem+'.tar.gz')) as archive:
                for member in archive.getmembers():
                    name=member.name.strip('/')
                    if name=='.':name=''
                    id,n=have[name]
                    assert n[1]&0o7777==member.mode&0o7777,(name,'mode')
                    assert n[2]==member.uid and n[3]==member.gid and n[5]==member.mtime,(name,'metadata')
                    if member.isfile() or member.issym():
                        data=archive.extractfile(member).read() if member.isfile() else member.linkname.encode()
                        assert probe(image,'read',id)==data,(name,'native bytes')
                        assert b''.join(w.read_file(id-1,len(data)))==data,(name,'reference bytes')
                        if opt.tools:assert run('icat',image,cli[name])==data,(name,'TSK bytes')
                    count+=1
            if opt.tools:
                assert cli=={p:id for p,(id,n) in have.items() if p}
                assert b'QNX ETFS' in run('fsstat',image)
            print(f'NFI {stem}: names, modes, owners, timestamps, symlinks and byte content match QNX tar',flush=True)
    print(f'{count} ETFS comparisons passed',flush=True)


if __name__=='__main__':main()
