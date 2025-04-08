# Testing

We have:

* Unit tests
* Acceptance tests

## Unit tests

Unit tests are low-level tests to verify a small piece of functionality. 
The `test/` directory contains a hierarchy that mirrors that of the Sleuthkit source; 
that hierarchy contains files corresponding to parts of the Sleuthkit source. 
E.g., `test/tsk/img` contains `test_img_io.cpp`, which has tests for functions in `tsk/img/img_io.cpp`.

Our unit tests are written using the Catch2 framework. Tests should be as short as possible and test one thing, ideally the input and output of single functions. If you're testing multiple scenarios, write multiple tests---the exception being data driven tests where the inputs and outputs can be checked in a loop. Checks which should halt the test on failure should use `REQUIRE`; Checks which should report failure but continue on should use `CHECK`.

* Any function that needs to work correctly ought to be unit-tested.
* Long functions are difficult to test, so please break long functions into multiple shorter functions to make them easier to test. This has the pleasant side-effect of making those functions easier to understand.

## Acceptance tests

Acceptance tests are high-level tests, possibly testing the complete output of a program. There are some basic image dump tests in `test/img_dump`, which uses a simple test tool to walk images and compare actual and expected output. Each of the Sleuthkit tools should have a script to drive acceptance tests in `test/tools/$TOOL` and expected output in `test/tools/$TOOL/$TOOL_output`, again which compares actual output with stored, expected output.

The purpose of acceptance tests is to catch changes in behavior which aren't caught by unit tests, perhaps due to gaps in the unit tests or changes to things outside the scope of unit tests, such as dependencies.

# New code and testing
New code is adopted through pull requests (PRs). 

## Bug-fix PRs

A PR which fixes a bug should contain:

1. A commit adding a test that fails due to the bug.
2. One or more commits to fix the bug. 

The fix commits should cause the failing test to pass.

## New functionality PRs

A PR containing new functionality should contain unit tests for new functions and acceptance tests for new user-facing functionality, 
in addition to updating any existing tests to match the changes.
