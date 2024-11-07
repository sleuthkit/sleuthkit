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
inline std::filesystem::path NamedTemporaryDirectory(std::string prefix,unsigned long long max_tries = 1000) {
    std::random_device dev;
    std::mt19937 prng(dev());
    std::uniform_int_distribution<uint64_t> rand(0);
    std::filesystem::path path;
    for (unsigned int i=0; i<max_tries; i++ ){
        std::stringstream ss;
        ss << prefix << "_" << std::hex << rand(prng);
        path = std::filesystem::temp_directory_path() / ss.str();
        if (std::filesystem::create_directory(path)) {
            return path;
        }
    }
    throw std::runtime_error("could not create NamedTemporaryDirectory");
}

namespace runner {
    bool contains(std::string line, std::string substr);
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
        std::filesystem::path temp_dir;
        std::filesystem::path temp_file_path;
        char *temp_file_path_buf;
        bool validate_contents(std::string substr);
        bool validate_contains(std::string substr);
        std::string first_tsk_utf8_line();
    };
}

#endif
