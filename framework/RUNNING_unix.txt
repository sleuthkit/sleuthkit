This file has some notes on how the code is organized.  It's a bit
complex because the framework needs a bunch of things to be in
exactly the right place, so we make the dev environment look kind
of like the installed environment.


BUILDING:
- Running configure and make in the framework folder should also
compile all of the modules.

- The TSK modules have mostly been configured to continue on even
if they have a critical dependency. You should see messages along
the way.  if you do not find a module, then try to compile it
manually by going into the 'modules' folder.

- Each module has some logic in it to detect if it is being compiled
as part of the framework or stand alone.  If part of the framework,
it will copy its configuration files to the 'runtime' folder.

- The top-level framework Makefile.am folder will make symlinks between
the compiled modules and the 'runtime' folder. 


RUNNING:
- tsk_analyzeimg has special logic to find the runtime folder if
you run it from the tsk_analyzeimg folder.

- The runtime folder is where you will find the framework config
file and module config files that you can edit while running
tsk_analyzeimg from its source folder (i.e. not an installed version).

