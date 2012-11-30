export AFFLIB_TRACEFILE=aftrace.txt
time ./fiwalk -C 10 /day2/VMs/winxp.aff > aftrace.time
gprof fiwalk gmon.out > aftrace.gmon.out


