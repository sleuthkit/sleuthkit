import fiwalk,math

total = 0 
total2 = 0
count = 0

def func(fi):
    global total,total2,count
    if fi.ext()=='txt':
        total += fi.filesize()
        total2 += fi.filesize() ** 2
        count += 1

fiwalk.fiwalk_using_sax(imagefile=open("small.dmg"),callback=func)
print "count=",count
print "average=",total/count
print "stddev=",math.sqrt(total2/count - (total/count)**2)

