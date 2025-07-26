#!/bin/bash -e

# check that the objects on the command line have no dependencies (or, in
# the case of Windows, no dependencies other than Windows system ones)

RET=0

while [[ $# -gt 0 ]]
do
  if [[ "$1" == *.dll || "$1" == *.exe ]]; then
    LIBS=$(objdump -x $1 | grep -Po 'DLL Name: \K.*' | (grep -Piv '(ADVAPI32|api-ms-win-core-path-l1-1-0|GDI32|KERNEL32|msvcrt|MSWSOCK|ole32|PSAPI|RPCRT4|SHELL32|SHLWAPI|USER32|WS2_32)\.dll' || [ $? -eq 1 ]))
  else
    LIBS=$(objdump -x $1 | grep -Po 'NEEDED\s+\K.*')
  fi
  if [[ "$LIBS" ]]; then
    LIBS=$(echo "$LIBS" | sed ':a;N;s/\n/, /;ba')
    echo "$1 is not static: depends on $LIBS"
    RET=1
  fi
  shift
done

exit $RET
