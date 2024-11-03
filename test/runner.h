/* helper functions for test runners.
 * (C) Simson L. Garfinkel, BasisTech LLC, 2024
 */

#ifndef RUNNER_H
#define RUNNER_H

#include <getopt.h>
#include <string>

namespace runner {
    bool contains(std::string line, std::string substr);
    std::string get_tempdir();
    void validate_file(std::string path, std::string contents);
    class save_getopt {
        int save_optind, save_opterr, save_optopt;
        char *save_optarg;
    public:
        save_getopt() {
            save_optarg = optarg;
            save_optind = optind;
            save_opterr = opterr;
            save_optopt = optopt;
        };
        ~save_getopt() {
            optarg = save_optarg;
            optind = save_optind;
            opterr = save_opterr;
            optopt = save_optopt;
        }
    };

    struct tempfile {
        tempfile(std::string testname);
        ~tempfile();
        FILE *file;
        int fd;
        std::string tempdir;
        char filename[64];
        bool validate_contents(std::string substr);
        bool validate_contains(std::string substr);
        std::string first_line();
    };
}

#endif
