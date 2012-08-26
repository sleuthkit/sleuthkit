import tre

fz = tre.Fuzzyness(maxerr = 3)
print fz

pt = tre.compile("Don(ald( Ervin)?)? Knuth", tre.EXTENDED)
data = """
In addition to fundamental contributions in several branches of
theoretical computer science, Donnald Erwin Kuth is the creator of the
TeX computer typesetting system, the related METAFONT font definition
language and rendering system, and the Computer Modern family of
typefaces.

"""

m = pt.search(data, fz)

if m:
    print m.groups()
    print m[0]
