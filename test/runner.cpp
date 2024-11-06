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
#include <iostream>
#include <fstream>
#include <memory>
#include <sys/stat.h>
#include <stdio.h>

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
        static std::string tempdir("/tmp");

        if (tempdir == std::string("/tmp")) {
            tempdir += "/" + testname + "_" + random_string(8);
#ifdef _MSC_VER
            mkdir(tempdir.c_str());
#else
            mkdir(tempdir.c_str(),0777);
#endif
            std::cerr << testname << " test results in: " << tempdir << std::endl;
        }
        return tempdir;
    }

    std::string file_contents(std::string path) {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        REQUIRE (in.is_open());
        auto size = in.tellg();
        std::unique_ptr<char[]>memblock(new char [size]);
        in.seekg (0, std::ios::beg);
        in.read (memblock.get(), size);
        in.close();
        return std::string(memblock.get(),size);
    }


    bool file_contents_is(std::string path, std::string contents) {
        return file_contents(path) == contents;
    }

    bool file_contains(std::string path, std::string substr) {
        return contains(file_contents(path), substr);
    }

    tempfile::tempfile(std::string testname) {
        tempdir = get_tempdir(testname);
        snprintf(filename,sizeof(filename),"%s/XXXXXX",tempdir.c_str());
        mkstemp(filename);
        file = fopen(filename,"w+");
        fd = fileno(file);
    }

    tempfile::~tempfile(){
        fclose(file);
        unlink(filename);
        unlink(tempdir.c_str());
    }

    bool tempfile::validate_contains(std::string contents) {
        fflush(file);
        fseeko(file,0L,0);
        return file_contains(filename, contents);
    }

    bool tempfile::validate_contents(std::string contents) {
        fflush(file);
        fseeko(file,0L,0);
        return file_contents_is(filename, contents);
    }

    std::string tempfile::first_line() {
        char buf[1024];
        memset(buf,0,sizeof(buf));
        fseek(file,0L,0);
        fgets(buf,sizeof(buf)-1,file);
        printf("buf=%s\n",buf);
        return buf;
    }
}
