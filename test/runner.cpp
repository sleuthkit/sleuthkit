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

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif


#include "utf8.h"

/* This program runs the catch2 test */

/* Support for runners */
namespace runner {
    std::filesystem::path NamedTemporaryDirectory(std::string prefix,unsigned long long max_tries = 1000) {
        std::random_device dev;
        std::mt19937 prng(dev());
        std::uniform_int_distribution<uint64_t> rand(0);
        std::filesystem::path path;
        for (unsigned int i=0; i<max_tries; i++ ){
            std::stringstream ss;
            ss << prefix << "_" << std::hex << rand(prng);
            path = std::filesystem::temp_directory_path() / ss.str();
            if (std::filesystem::create_directory(path)) {
                std::cerr << "named temporary directory: " << path << "\n";
                return path;
            }
        }
        throw std::runtime_error("could not create NamedTemporaryDirectory");
    }

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

    std::string file_contents(std::filesystem::path path) {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        REQUIRE (in.is_open());
        auto size = in.tellg();
        std::unique_ptr<char[]>memblock(new char [size]);
        in.seekg (0, std::ios::beg);
        in.read (memblock.get(), size);
        in.close();
        return std::string(memblock.get(),size);
    }

    std::u16string file_contents16(std::filesystem::path path) {
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        REQUIRE (in.is_open());
        auto size = in.tellg();
        std::unique_ptr<char[]>memblock(new char [size]);
        in.seekg (0, std::ios::beg);
        in.read (memblock.get(), size);
        in.close();
        return std::u16string(reinterpret_cast<const char16_t*>(memblock.get()), size / 2);
    }

    /* On Mac & Linux, return file contents.
     * On Windows, convert utf16 file content to utf-8
     */
    bool file_contents_is(std::filesystem::path path, std::string contents) {
        return file_contents(path) == contents;
    }

    bool file_contains(std::filesystem::path path, std::string substr) {
        return contains(file_contents(path), substr);
    }

    tempfile::tempfile(std::string testname) {
        // Create a writable copy of the path string for mkstemp
        temp_dir = NamedTemporaryDirectory(testname);
        auto tmpl        = temp_dir / (testname + std::string("XXXXXX"));
        auto tmpl_string = tmpl.string();
        std::cerr << "tmpl_string: " << tmpl_string << "\n";
        char *tmpl_buf = strdup(tmpl_string.c_str());

        // Use mkstemp to create a unique temporary file
        std::cerr << "tmpl_buf:" << tmpl_buf << "\n";
        fd = mkstemp(tmpl_buf);
        std::cerr << "tmpl_buf:" << tmpl_buf << "\n";
        if (fd == -1) {
            throw std::runtime_error("Failed to create temporary file");
        }
        close(fd);        // Windows defaults to exclusive access. We do not want that
        temp_file_path = tmpl_buf;      // retain
        file = fopen(tmpl_buf,"wb+");         // open the FILE
        if (file==NULL) {
            throw std::runtime_error("fopen() failed");
        }
        free(tmpl_buf);                 //
    }

    tempfile::~tempfile(){
        fclose(file);
        close(fd);
        std::cerr << "remove_all " << temp_file_path << "\n";
        std::cerr << "remove_all " << temp_dir << "\n";
        std::filesystem::remove_all(temp_file_path);
        std::filesystem::remove_all(temp_dir);
    }

    bool tempfile::validate_contains(std::string contents) {
        fflush(file);
        fseeko(file,0L,0);
        return file_contains(temp_file_path, contents);
    }

    bool tempfile::validate_contents(std::string contents) {
        fflush(file);
        fseeko(file,0L,0);
        return file_contents_is(temp_file_path, contents);
    }

#ifdef _WIN32
    /* On windows, TSK is writing out UTF16 lines; convert them */
    std::string tempfile::first_tsk_utf8_line() {
        std::ifstream in(temp_file_path);
        if (!in.is_open()){
            std::cerr << "tempfile: " <<temp_file_path << "\n";
            throw std::runtime_error("cannot open tempfile");
        }

        // Skip BOM if present (UTF-16 LE: 0xFF 0xFE, UTF-16 BE: 0xFE 0xFF)
        char16_t bom;
        in.read(reinterpret_cast<char*>(&bom), sizeof(bom));
        if (bom != 0xFEFF) {
            // Not a BOM, rewind
            in.seekg(0);
        }

        std::u16string line;
        char16_t ch;
        while (in.read(reinterpret_cast<char*>(&ch), sizeof(ch))) {
            if (ch == u'\n') {
                break;
            } else {
                line += ch;
            }
        }
        return utf8::utf16to8( line );
    }
#else
    /* On non-windows, TSK is writing out UTF8 lines */
    std::string tempfile::first_tsk_utf8_line() {
        std::ifstream in(temp_file_path );
        std::cerr << "reading " << temp_file_path << "\n";
        if (!in.is_open()) {
            std::cerr << "temp_file_path: " << temp_file_path << "\n";
            std::string msg = std::string("cannot open tempfile ") + std::string(temp_file_path);
            throw std::runtime_error(msg);
        }
        std::string line;
        if (std::getline(in, line)) {
            std::cerr << "line:" << line << "\n";
            return line;
        }
        std::cerr << "no first line\n";
        throw std::runtime_error("no first line");
    }
#endif
}
