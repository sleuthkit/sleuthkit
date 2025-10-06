/* 
* Author: Taha Ebrahim @Taha-Ebrahim
* Purpose: Utilities for CLI based testing of TSK. 
* Works with tsk_cli_runner.cpp to run tests stored in cli_tests.txt.
*/
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <chrono>
#include <cstdio>
#include <iomanip>

#include "tsk_tempfile.h"
#include "test_utils.h"

bool parse_test_line(const std::string& line,
    std::string& id,
    std::string& cmd,
    std::string& expected_stdout_path,
    int& expected_exit,
    std::string& expected_stderr_path)
{
    size_t pos1 = line.find('|');
    size_t pos2 = line.find('|', pos1 + 1);
    size_t pos3 = line.find('|', pos2 + 1);
    size_t pos4 = line.find('|', pos3 + 1);

    if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos)
    return false;

    id = line.substr(0, pos1);
    cmd = line.substr(pos1 + 1, pos2 - pos1 - 1);
    expected_stdout_path = line.substr(pos2 + 1, pos3 - pos2 - 1);

    if (pos4 == std::string::npos) {
        // Only 4 fields provided
        expected_exit = std::stoi(line.substr(pos3 + 1));
        expected_stderr_path = "";
    } else {
        expected_exit = std::stoi(line.substr(pos3 + 1, pos4 - pos3 - 1));
        expected_stderr_path = line.substr(pos4 + 1);
    }
    return true;
}

std::string read_file(FILE* file) {
    fflush(file);
    fseek(file, 0, SEEK_SET);

    std::ostringstream ss;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
        ss.write(buf, n);
    }

    return ss.str();
}

bool compare_files(FILE* expected, FILE* actual) {
    std::string expected_content = read_file(expected);
    std::string actual_content = read_file(actual);
    
    if (expected_content != actual_content) {
        std::cout << "Expected File: " << expected_content << '\n';
        std::cout << "Output: " << actual_content << '\n';
    }

    return expected_content == actual_content;
}

void print_diff(const std::string& expected, const std::string& actual) {
    std::istringstream expected_stream(expected);
    std::istringstream actual_stream(actual);

    std::string expected_line, actual_line;
    int line_num = 1;
    while (std::getline(expected_stream, expected_line) &&
           std::getline(actual_stream, actual_line)) {
        if (expected_line != actual_line) {
            std::cout << "  Line " << line_num << " differs:\n";
            std::cout << "    Expected: \"" << expected_line << "\"\n";
            std::cout << "    Actual  : \"" << actual_line << "\"\n";
        }
        ++line_num;
    }

    // Handle extra lines
    while (std::getline(expected_stream, expected_line)) {
        std::cout << "  Line " << line_num << " missing in actual output:\n";
        std::cout << "    Expected: \"" << expected_line << "\"\n";
        ++line_num;
    }

    while (std::getline(actual_stream, actual_line)) {
        std::cout << "  Extra line " << line_num << " in actual output:\n";
        std::cout << "    Actual  : \"" << actual_line << "\"\n";
        ++line_num;
    }
}

std::string adjust_tool_path(const std::string& raw_command) {
    std::string cmd = raw_command;

    const char* wine = std::getenv("WINE");
    const char* exeext = (wine && *wine) ? ".exe" : "";
    const char* srcdir = std::getenv("srcdir");
    const char* data_dir = std::getenv("DATA_DIR");
    const char* tsk_dir = std::getenv("SLEUTHKIT_TEST_DATA_DIR");

    std::string datadir = data_dir ? data_dir : (srcdir ? std::string(srcdir) + "/test/data" : "");
    std::string sleuthkit_data = tsk_dir ? tsk_dir : "";

    size_t pos;
    while ((pos = cmd.find("$EXEEXT")) != std::string::npos)
        cmd.replace(pos, 7, exeext);
    while ((pos = cmd.find("$DATA_DIR")) != std::string::npos)
        cmd.replace(pos, 10, datadir);
    while ((pos = cmd.find("$SLEUTHKIT_TEST_DATA_DIR")) != std::string::npos)
        cmd.replace(pos, 24, sleuthkit_data);

    return cmd;
}


int run_test(const std::string& cmd, 
    FILE* expected_stdout,
    FILE* expected_stderr, 
    int expected_exit, 
    TestResult& result) 
{
    if (cmd.find("$SLEUTHKIT_TEST_DATA_DIR") != std::string::npos) {
        const char* test_data_dir = std::getenv("SLEUTHKIT_TEST_DATA_DIR");
        if (!test_data_dir || !*test_data_dir) {
            std::cout << "[skip] Test \"" << result.id 
                      << "\" references $SLEUTHKIT_TEST_DATA_DIR, but it is not set.\n";
            result.skipped = true;
            return 0;
        }
    }
    
    std::string resolved_cmd = adjust_tool_path(cmd);

    // Use named tempfile for command output
    std::string stdout_path, stderr_path;
    FILE* out_file = tsk_make_named_tempfile(&stdout_path);
    FILE* err_file = tsk_make_named_tempfile(&stderr_path);

    if (!out_file || !err_file) {
        std::cerr << "Failed to create temp file for command output.\n";
        result.error = true;
        return 1;
    }

    std::fclose(out_file);
    std::fclose(err_file);
    std::string full_cmd;

    if (expected_stderr) {
        full_cmd = resolved_cmd + " > \"" + stdout_path + "\" 2> \"" + stderr_path + "\"";

    } else {
        full_cmd = resolved_cmd + " > \"" + stdout_path + "\"";
    }

    int exit_code = std::system(full_cmd.c_str());

#if defined(_WIN32) && defined(__MINGW32__)
    result.actual_exit = exit_code;
#else
    result.actual_exit = WEXITSTATUS(exit_code);
#endif

    // Read actual output from temp file
    std::ifstream tmpin(stdout_path.c_str());
    std::ostringstream actual_output_stream;
    actual_output_stream << tmpin.rdbuf();
    std::string actual_output = actual_output_stream.str();
    tmpin.close();
    std::remove(stdout_path.c_str());

    // Read expected output
    std::string expected_output = read_file(expected_stdout);

    // Normalize timezone abbreviation differences
    std::string normalized_expected = expected_output;
    std::string normalized_actual = actual_output;

    auto fix_timezone = [](std::string& s) {
        size_t pos;
        while ((pos = s.find(" (UT)")) != std::string::npos)
            s.replace(pos, 5, " (UTC)");
    };

    fix_timezone(normalized_expected);
    fix_timezone(normalized_actual);

    result.stdout_match = (normalized_actual == normalized_expected);
    if (!result.stdout_match) {
        std::cout << "  [diff] stdout mismatch in test: " << result.id << "\n";
        print_diff(normalized_expected, normalized_actual);
    }

    if (expected_stderr) {
        std::ifstream tmpin(stderr_path.c_str());
        std::ostringstream actual_error_stream;
        actual_error_stream << tmpin.rdbuf();
        std::string actual_error = actual_error_stream.str();
        tmpin.close();
        std::remove(stderr_path.c_str());
        
        std::string expected_error = read_file(expected_stderr);
        result.stderr_match = (actual_error == expected_error);
        if (!result.stderr_match) {
            std::cout << "  [diff] stderr mismatch in test: " << result.id << "\n";
            print_diff(expected_error, actual_error);
        }
    } else {
        result.stderr_match = true;
    }
    
    result.error = (result.actual_exit != expected_exit || !result.stdout_match || !result.stderr_match);

    return result.error ? 1 : 0;
}



// Print result summary table
void print_summary(const std::vector<TestResult>& results) {
    std::cout << "\nTest Summary:\n";
    std::cout << std::setw(12) << "Test ID"
        << std::setw(10) << "Exit"
        << std::setw(10) << "Match"
        << "\n";

    for (const auto& r : results) {
        std::cout << std::setw(12) << r.id
          << std::setw(10) << r.actual_exit
          << std::setw(10) << (r.skipped ? "skipped" :
                              (r.stdout_match && r.stderr_match ? "yes" : "NO"))
          << "\n";

        if (!r.skipped) {
            if (!r.stdout_match) {
                std::cout << "  stdout mismatch for test: " << r.id << "\n";
            }
            if (!r.stderr_match) {
                std::cout << "  stderr mismatch or unexpected stderr in: " << r.id << "\n";
            }
        }
        if (results.empty()) {
            std::cout << "[!] No tests were run or no results were recorded.\n";
        }
    }
}

// Run all tests from definition file
int run_all_tests() {

    int tests_run = 0, tests_skipped = 0, tests_failed = 0;
    std::vector<TestResult> results;

    std::ifstream infile("test/tools/cli_tests.txt");
    if (!infile) {
        perror("open");
    }


    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::string id, cmd, expected_out_path, expected_err_path;
        int expected_exit;
        if (!parse_test_line(line, id, cmd, expected_out_path, expected_exit, expected_err_path)) {
            std::cerr << "Invalid line: " << line << "\n";
            continue;
        }

        TestResult result{id, cmd, expected_exit};
        tests_run++;

        if (cmd.empty()) {
            result.skipped = true;
            tests_skipped++;
        } else {
            FILE* expected_out = fopen(expected_out_path.c_str(), "r");
            FILE* expected_err = nullptr;
            
            if (!expected_out) {
                std::cerr << "Failed to open expected output file: " << expected_out_path << "\n";
                result.error = true;
            } 

            if (!expected_err_path.empty()) {
                expected_err = fopen(expected_err_path.c_str(), "r");
                if (!expected_err) {
                    std::cerr << "Failed to open expected error file: " << expected_err_path << "\n";
                    result.error = true;
                }
            }
            
            if (!result.error) {
                run_test(cmd, expected_out, expected_err, expected_exit, result);
                if (result.skipped) {
                    tests_skipped++;
                } else if (result.error) {
                    tests_failed++;
                }
            } else {
                tests_failed++;
            }
            if (expected_err) fclose(expected_err);
            if (expected_out) fclose(expected_out);
        }
        results.push_back(result);
    }

    print_summary(results);

    std::cout << "\nTests run: " << tests_run
        << ", Skipped: " << tests_skipped
        << ", Failed: " << tests_failed << "\n";
    if (tests_failed > 0) {
        return 1;
    }
    else if (tests_skipped > 0) {
        return 77;
    }
    else {
        return 0;
    }
}