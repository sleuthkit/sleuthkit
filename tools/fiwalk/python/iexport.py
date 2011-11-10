#!/usr/bin/env python
"""iexport.py: export the unallocated spaces."""


class Run:
    """Keeps track of a single run"""
    def __init__(self,start,len):
        self.start = start
        self.len = len
        self.end = start+len-1
    def __str__(self):
        return "Run<%d--%d> (len %d)" % (self.start,self.end,self.len)
    def contains(self,b):
        """Returns true if b is inside self."""
        print "%d <= %d <= %d = %s" % (self.start,b,self.end,(self.start <= b <= self.end))
        return self.start <= b <= self.end
    def intersects_run(self,r):
        """Return true if self intersects r.  This may be because r.start is
        inside the run, r.end is inside the run, or self is inside the run."""
        return self.contains(r.start) or self.contains(r.end) or r.contains(self.start)
    def contains_run(self,r):
        """Returns true if self completely contains r"""
        return self.contains(r.start) and self.contains(r.end)
        

class RunDB:
    """The RunDB maintains a list of all the runs in a disk image. The
RunDB is created with a single run that represnts all of the sectors
in the disk image. Runs can then be removed, which causes existing
runs to be split. Finally all of the remaining runs can be removed."""
    def __init__(self,start,len):
        self.runs = [ Run(start,len) ]
    def __str__(self):
        return "RunDB\n" + "\n".join([str(p) for p in self.runs])
    def intersecting_runs(self,r):
        """Return a list of all the Runs that intersect with r.
        This may be because r.start is inside the run, r.end is inside
        the run, because the run completely encloses r, or becuase r completely
        encloses the run."""
        return filter(lambda x:x.intersects_run(r) , self.runs)
    def remove(self,r):
        """Remove run r"""
        for p in self.intersecting_runs(r):
            self.runs.remove(p)

            # if P is completely inside r, just remove it
            if r.contains_run(p):
                continue

            # Split p into before and after r; add the non-zero pieces
            before_len = r.start - p.start
            if before_len>0:
                self.runs.append(Run(p.start,before_len))
            after_len = p.end - r.end
            if after_len>0:
                self.runs.append(Run(r.end,after_len))
                

if __name__=="__main__":
    r1 = Run(0,1000)
    r2 = Run(50,60)
    assert r1.intersects_run(r2)
    assert r2.intersects_run(r1)

    disk = RunDB(0,1000)
    print disk
    disk.remove(Run(50,60))
    disk.remove(Run(0,10))
    disk.remove(Run(40,20))
    print disk

