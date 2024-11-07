/* helper functions for test runners.
 * (C) Simson L. Garfinkel, BasisTech LLC, 2024
 */

#ifndef RUNNER_H
#define RUNNER_H

#include <getopt.h>
#include <string>
#include <sstream>
#include <random>
#include <filesystem>

// https://stackoverflow.com/questions/3379956/how-to-create-a-temporary-directory-in-c
namespace runner {
    bool contains(std::string line, std::string substr);
    void validate_file(std::string path, std::string contents);

    struct tempfile {
        tempfile(std::string testname);
        ~tempfile();
        FILE *file;
        int fd;
        std::filesystem::path temp_dir;
        std::filesystem::path temp_file_path;
        char *temp_file_path_buf;
        bool validate_contents(std::string substr);
        bool validate_contains(std::string substr);
        std::string first_tsk_utf8_line();
    };
}

#endif
