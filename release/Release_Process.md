SleuthKit 4.13 Release Process
------------------------------

Write release notes
-------------------
Write release notes that do more than summarize the git log (which will be long this time.)


Document updates
----------------

`git log --pretty="%h - %s (%an)" sleuthkit-4.12.0..HEAD`

Testing Code
------------
Final release testing is by Brian Carrier on his personal machine.
- Run regression tests (`tests/reg-test.pl`)
- Compile on Cygwin

Build Unix Tarball
------------------
Run: `release-unix.pl 4.X.X`

NOTE: The above can be done on the Basis computers, but it doesn’t have the GPG key to sign. The process will finish though. Just sign on personal computer after.
Archive the tar ball by moving it from the release directory to a non-git directory (../../release)


Windows Release (after running release-unix, which does tagging)
----------------------------------------------------------------
- Repo can be on develop or wherever. Script does the pull and checkout.
- Get latest version of libewf
- Double click on VS015_cygwin.bat
- Change to the release folder
- Run `./release-win.pl 4.13.0` (version only)
- Verify contents of release directory (sanity check)
  - NOTE: DELETE `Rejistry++ .lib` file - it adds 20MB.
- Copy over to OS X system into release directory for signing

Make Github Release
------------------
- Make a release based on the tag.
- Add the release notes
- Upload the tgz, asc and zip files

Cleanup Github Branches
-----------------------
- [ ] git pull  (to get changes from branch)
- [ ] git checkout master
- [ ] git pull
- [ ] git merge release-X
- [ ] git push origin master
- [ ] git checkout develop
- [ ] git pull
- [ ] git merge release-X
- [ ] git push origin develop

Website
------
1) Update index.html with release
2) Update sleuthkit/download with version info
X) Update history (using NEWS.txt), download, index, and  RSS Feed
