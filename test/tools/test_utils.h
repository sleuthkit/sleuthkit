/* 
* Author: Taha Ebrahim @Taha-Ebrahim
* Purpose: Header file for test-utils.cpp. 
*/
#ifndef TSK_CLI_RUNNER_H
#define TSK_CLI_RUNNER_H

#include <string>
#include <vector>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <chrono>
#include <iomanip>

// Struct to store result of a single test case
struct TestResult {
    std::string id;
    std::string cmd;
    int expected_exit;
    int actual_exit = 1;
    bool stdout_match = false;
    bool stderr_match = false;
    bool skipped = false;
    bool error = false;
};

// Parses a single line from the test file.
// Returns true if the line is well-formed, false otherwise.
bool parse_test_line(const std::string& line,
                     std::string& id,
                     std::string& cmd,
                     std::string& expected_stdout_path,
                     int& expected_exit,
                     std::string& expected_stderr_path);

// Reads and returns the contents of the given FILE*.
std::string read_file(FILE* file);

// Compares the contents of two FILE* streams.
bool compare_files(FILE* expected, FILE* actual);

// Prints the line-by-line diff between expected and actual output.
void print_diff(const std::string& expected, const std::string& actual);

// Replaces placeholder paths like $EXEEXT and $DATA_DIR in command strings.
std::string adjust_tool_path(const std::string& raw_command);

// Runs a single test case and populates the result object.
// Returns 1 if the test fails, 0 otherwise.
int run_test(const std::string& cmd, 
             FILE* expected_stdout,
             FILE* expected_stderr, 
             int expected_exit, 
             TestResult& result);

// Prints a summary of all test results to stdout.
void print_summary(const std::vector<TestResult>& results);

// Loads and runs all tests from cli_tests.txt.
// Returns 0 on success (all tests passed), 1 otherwise.
int run_all_tests();

#endif // TSK_CLI_RUNNER_H