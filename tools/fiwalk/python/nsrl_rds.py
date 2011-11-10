#!/usr/bin/env python
#
# Demonstrates how to communicate with NPS NSRL RDS
#

RDS_SERVER = "https://domex.nps.edu/www-noauth/nsrl_rds.cgi"

import xmlrpclib


if __name__=="__main__":
    print("Demonstration of NSRL RDS service at %s\n" % RDS_SERVER)
    print("")
    p = xmlrpclib.ServerProxy(RDS_SERVER)
    try:
        avail = p.available()
    except xmlrpclib.ProtocolError as e:
        print("Cannot access "+RDS_SERVER)
        print(e)
        raise RuntimeError

        
    print("Available RDS sets: %s " % avail)

    md5_val = "EB714443AA2FC1A3D16E39EB8007A0B2"

    # Build a search term
    search = {"db":avail[0],      # pick the first search term
              "md5":md5_val
              } 
              
    print("Here are the files with a md5 of "+md5_val)
    ret = p.search(search)
    fields = ret['fields']
    for row in ret['result']:
        for(a,b) in zip(fields,row):
            print a,"=",b
        print ""
        
    print("Now we will do a query for multiple MD5 values. You can do this by specifying\n"+
          "a value as an array.")
    searchm = {"db":avail[0],
               "md5":["EB714443AA2FC1A3D16E39EB8007A0B2",
                      "9B3702B0E788C6D62996392FE3C9786A"]}
    print "sending:",searchm
    ret = p.search(searchm)
    print "got:",ret
    fields = ret['fields']
    for row in ret['result']:
        for(a,b) in zip(fields,row):
            print a,"=",b
        print ""
        

