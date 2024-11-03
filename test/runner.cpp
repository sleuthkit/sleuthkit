/*
 * The Sleuth Kit
 *
 *
 * Copyright (c) 2010, 2025 Basis Technology Corp.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_CONSOLE_WIDTH 120

#include "catch.hpp"
#include "runner.h"
#include <memory>

/* This program runs the catch2 test */

/* Support for runners */
namespace runner {
    // https://inversepalindrome.com/blog/how-to-create-a-random-string-in-cpp
    std::string random_string(std::size_t length) {
        const std::string CHARACTERS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        std::random_device random_device;
        std::mt19937 generator(random_device());
        std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

        std::string random_string;

        for (std::size_t i = 0; i < length; ++i) { random_string += CHARACTERS[distribution(generator)]; }

        return random_string;
    }

    bool contains(std::string line, std::string substr) {
        return line.find(substr) != std::string::npos;
    }

    std::string get_tempdir(std::string testname) {
        static std::filesystem::string tempdir("/");

        if (tempdir == std::filesystem::string("/")) {
            tempdir = std::filesystem::temp_directory_path() + "/" + testname + "_" + random_string(8);
            std::filesystem::create_directory(tempdir);
            std::cerr << testname << " test results in: " << tempdir << std::endl;
        }
        return tempdir;
    }

    bool file_contents_is(std::filesystem::path path, std::string contents) {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        REQUIRE (in.is_open());
        auto size = in.tellg();
        std::unique_ptr<char>memblock = new char [size];
        in.seekg (0, std::ios::beg);
        in.read (memblock, size);
        in.close();
        std::string str(memblock,size);
        return str == contents;
    }

    tempfile::tempfile(std::string testname) {
        tempdir = get_tempdir(testname);
        snprintf(filename,sizeof(filename),"%s/XXXXXX",tempdir.c_str());
        mkstemp(filename);
        f = fopen(filename,"w+");
        fd = fileno(f);
    }

    tempfile::~tempfile(){
        fclose(fd);
        unlink(filename);
        unlink(tempdir.c.str());
    }

    bool tempfile::validate_contents(std::string contents) {
        fflush(f);
        fseeko(f,0L,0);
        return file_contents_is(filename, contents);
    }

    bool tempfile::validate_contents(std::string contents) {
        fflush(f);
        fseeko(f,0L,0);
        return file_contents_is(filename, contents);
    }

    std::string tempfile::first_line() {
        char buf[1024];
        fseek(f,0L,0);
        return fgets(f,buf,sizeof(buf));
    }
}
