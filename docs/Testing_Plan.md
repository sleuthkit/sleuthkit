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

## CLI Test Runner Specification

### Overview

This section describes a new C++-based CLI test runner being introduced to improve the automation and consistency of testing command-line tools in Sleuth Kit (TSK). The runner reads a structured test definition file, executes the specified commands, and compares their outputs against expected results (both stdout and stderr), validating correctness and exit codes.

### Test Definition Format

Test definitions are stored in a plain text file (e.g., `cli_tests.txt`), with each line defining a single test case using the following pipe-delimited format: `TestID|CLICommand|ExpectedOutputFilePath|ExpectedExitCode`

- Lines beginning with `#` are treated as comments.
- A corresponding file `<TestID>.stderr` may optionally be provided in the same directory and will be automatically loaded if present.
- If no `.stderr` file exists, stderr is expected to be empty.

Example: `hello_1|echo "Hello World"|test/tools/output/hello.stdout|0`

### Execution Strategy

The test runner performs the following steps for each test:

1. Parse each line from the test definition file, skipping comments.
2. Extract: TestID, CLICommand, ExpectedOutputFilePath, and ExpectedExitCode.
3. Redirect command output to temporary files:
   - stdout → temporary file
   - stderr → temporary file
4. Validate:
   - Exit code matches ExpectedExitCode
   - stdout matches contents of expected file
   - stderr matches corresponding stderr output, if present
     - If not present, stderr must be empty
5. Report mismatches using diff if available
6. Record results and increment counters:
   - Total run
   - Skipped (if command is empty or fails to execute)
   - Failed (output mismatch or incorrect exit)
7. Summarize in a formatted result table

### Summary Output

After running, the tool prints a table like:
Test Summary:
Test ID Exit Match
hello_1 0 yes 

Tests run: 1, Skipped: 0, Failed: 0

### Temporary Output Handling

To maintain cross-platform compatibility:

- Temporary files are created using the `tsk_make_tempfile()` utility.

### Implementation Status
The basic framework of the CLI test runner is near-complete, including parsing of the test definition file, execution of the specified CLI commands, redirection of output streams to temporary files, and comparison against expected outputs. Currently work is being completed to fit the elements of the new test runner together. 