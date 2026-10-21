"""Independent literals from the NFI/QNX ETFS layout; no parser constants imported."""
import struct


def fixture(page=1024):
    records=[b'\xff'*64 for _ in range(32)]
    def entry(fid,parent,mode,name,size=0,ext=0):
        records[fid]=(struct.pack('<HH7I',ext,parent,mode,123,456,1700000000,1700000001,1700000002,size)
                      +name.encode()[:32].ljust(32,b'\0'))
    entry(0,0,0o40755,'')
    for fid,name in enumerate(('.filetable','.badblks','.counts','.lost+found','.reserved'),1):
        entry(fid,0,0o40755 if fid==4 else 0o100444,name)
    payload=b'current ETFS payload\n'
    entry(6,0,0o100640,'status.txt',len(payload))
    entry(7,0,0o40750,'nested')
    longname='a-very-long-vehicle-record-name-with-extension.bin'
    content=b'prefix'.ljust(page,b'P')+b'\xff'*page+b'tail'
    entry(8,7,0o100600,longname,len(content),9)
    records[9]=struct.pack('<HH',0x8000,8)+longname.encode()[32:].ljust(59,b'\0')+b'\0'
    entry(10,0,0o120777,'link',len(b'nested/'+longname.encode()))
    entry(11,99,0o100644,'orphan.txt',6)
    entry(12,0xffff,0o100644,'deleted.txt',5)
    entry(13,0,0o100644,'empty.txt')
    entry(14,0,0o100644,'missing.bin',page+3)
    entry(15,0,0o100644,'last.txt',4)
    pages=[]
    def trans(fid,cluster,seq,data,ta=0):
        pages.append(data.ljust(page,b'\xff')+struct.pack('<IIHBBI',fid,cluster,1,ta,0,seq))
    table=b''.join(records)
    table=table.ljust(((len(table)+page-1)//page)*page,b'\xff')
    for cluster in range(len(table)//page):trans(1,cluster,20,table[cluster*page:(cluster+1)*page])
    trans(6,0,1,b'HISTORICAL-ETFS-MARKER\n')
    trans(6,0,5,b'earlier equal-sequence page')
    trans(6,0,5,payload)
    trans(6,0,99,b'invalid transaction must not win',ta=5)
    trans(8,2,2,b'tail',ta=1)
    trans(8,0,2,b'prefix'.ljust(page,b'P'))
    trans(10,0,2,b'nested/'+longname.encode())
    trans(11,0,2,b'orphan')
    trans(12,0,2,b'DELETED-ETFS-MARKER')
    trans(15,0,2,b'last')
    pages.append(b'\xff'*(page+16))
    expected={'status.txt':payload,'nested/'+longname:content,
              'link':b'nested/'+longname.encode(),'$ETFS_Orphans/orphan.txt':b'orphan',
              'empty.txt':b'','missing.bin':b'\xff'*(page+3),'last.txt':b'last'}
    return b''.join(pages),expected
