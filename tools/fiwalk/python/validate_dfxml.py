import sys, fiwalk, os.path
from optparse import OptionParser
from sys import stdout
 
def demo_dfxml_time_bug(filename):
    parser = OptionParser()
    parser.usage = '%prog% [options] xmlfile '
    (options,args) = parser.parse_args()
    for fi in fiwalk.fileobjects_using_sax(xmlfile=open(filename,"rb")):
        fsize = fi.filesize()
        try:
            mt = fi.mtime()
            print('Type of mt:',type(mt))
            print('Normal mtime:')
            print(mt)
        except KeyboardInterrupt:
            raise
        except:
            raise
            print('Abnormal mtime for file with size',fsize)
 
if __name__=="__main__":
    filename = sys.argv[1]
    demo_dfxml_time_bug(filename)
