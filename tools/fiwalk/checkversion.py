import sys
server_version = open(sys.argv[1],"r").read().strip()
print "Server Version:",server_version
if(server_version == sys.argv[2]):
    print "\n\nVersion",sys.argv[1],"is already on the server.\n\n"
    sys.exit(-1)
sys.exit(0)
