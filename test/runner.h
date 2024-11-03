/* helper functions for test runners.
 * (C) Simson L. Garfinkel, BasisTech LLC, 2024
 */

#ifndef RUNNER_H
#define RUNNER_H

#include <string>

namespace runner {
    bool contains(std::string line, std::string substr);
    std::string get_tempdir();
    void validate_file(std::filesystem::path path, std::string contents);
    struct tempfile {
        tempfile(std::string testname);
        ~tempfile();
        FILE *f;
        int fd;
        std::string tempdir;
        char filename[64];
        bool validate_contains(std::string substr);
    }
}

#endif
