/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

// Utility methods for recording errors/debug messages

#ifdef HAVE_LIBMBEDTLS

#include "BitlockerUtils.h"
#include "tsk/base/tsk_base_i.h"

#include <sstream>
#include <iomanip>

/**
* Record an error message.
* Save the error and write to output if in verbose mode.
* There is a good chance any error code saved here will be
* overwritten during the file system open process.
* 
* @param errMes  The error message
*/
void writeError(string errMes) {
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_BITLOCKER_ERROR);
    tsk_error_set_errstr(errMes.c_str());

    if (tsk_verbose) {
        tsk_fprintf(stderr, "%s\n", errMes.c_str());
        fflush(stderr);
    }
}

/**
* Record a warning message.
* Current the same as recording a debug message - writes a message if we're in verbose mode.
* 
* @param warningMes  The warning message
*/
void writeWarning(string warningMes) {
    if (tsk_verbose) {
        tsk_fprintf(stderr, "%s\n", warningMes.c_str());
    }
}

/**
* Record a debug message.
* Writes a message if we're in verbose mode.
*
* @param debugMes  The debug message
*/
void writeDebug(string debugMes) {
    if (tsk_verbose) {
        tsk_fprintf(stderr, "%s\n", debugMes.c_str());
        fflush(stderr);
    }
}

/**
* Convert a byte array into a string of hex digits.
* Ex: "5502df1a"
* 
* @param bytes   The byte array
* @param len     Size of byte array (or number of bytes to print if less than the size)
* 
* @return String containing hex values
*/
string convertByteArrayToString(uint8_t* bytes, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; i++) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (bytes[i] & 0xff);
    }
    return ss.str();
}

/**
* Convert a uint32_t value into a hex string
* Ex: "0x000056ab"
* 
* @param val  32-bit value to convert to string
* 
* @return val as a string
*/
string convertUint32ToString(uint32_t val) {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << val;
    return ss.str();
}

/**
* Convert a uint64_t value into a hex string
* Ex: "0x00000000000056ab"
* 
* @param val  64-bit value to convert to string
* 
* @return val as a string
*/
string convertUint64ToString(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << val;
    return ss.str();
}

#endif