html = False

def header():
    if html:
        print("""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN http://www.w3.org/TR/html4/loose.dtd">
<html>
<body>
<style>
body  { font-family: Sans-serif;}
.sha1 { font-family: monospace; font-size: small;}
.filesize { padding-left: 15px; padding-right: 15px; text-align: right;}
</style>
""")

def h1(title):
    global options
    if html:
        print("<h1>%s</h1>" % title)
        return
    print("\n\n%s\n" % title)

def h2(title):
    global options
    if html:
        print("<h2>%s</h2>" % title)
        return
    print("\n%s\n" % title)


def table(rows,styles=None,break_on_change=False):
    import sys
    global options
    def alldigits(x):
        if type(x)!=str and type(x)!=unicode: return False
        for ch in x:
            if ch.isdigit()==False: return False
        return True

    def fmt(x):
        if x==None: return ""
        if type(x)==int: return "%12d" % x
        if alldigits(x): return "%12d" % int(x)
        if type(x)==unicode: return x
        return unicode(x)
            
    if html:
        print("<table>")
        for row in rows:
            print("<tr>")
            if not styles:
                styles = [""]*len(rows)
            for (col,style) in zip(row,styles):
                sys.stdout.write("<td class='%s'>%s</td>" % (style,col))
            print("<tr>")
        print("</table>")
        return
    lastRowCol0 = None
    for row in rows:
        if row[0]!=lastRowCol0:
            sys.stdout.write("\n")
            lastRowCol0 = row[0]
        try:
            line = "\t".join([fmt(col) for col in row])
            sys.stdout.write(line)
            sys.stdout.write("\n")
        except UnicodeEncodeError:
            # Fall back to manual join
            for col in row:
                for ch in fmt(col):
                    try: 
                        sys.stdout.write(ch)
                    except UnicodeEncodeError:
                        sys.stdout.write('?');
                sys.stdout.write("\t")
            print("(UNICODE ERROR)")

