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

#include <sstream>
#include <iomanip>

/**
* Record an error message.
*/
void writeError(string errMes) {
    /* TODO - switch to this once the code is in TSK
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("fatfs_open: sector size is 0");
    */
    //printf("writeError: %s\n", errMes.c_str());
    //fflush(stdout);
}

/**
* Record a warning message.
*/
void writeWarning(string errMes) {
    /* TODO - switch to this once the code is in TSK
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("fatfs_open: sector size is 0");
    */
    //printf("writeWarning: %s\n", errMes.c_str());
    //fflush(stdout);
}

void writeDebug(string msg) {
    //printf("Debug: %s\n", msg.c_str());
    //fflush(stdout);
}

/**
* Convert a byte array into a string of hex digits
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
*/
string convertUint32ToString(uint32_t val) {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << val;
    return ss.str();
}

/**
* Convert a uint64_t value into a hex string
*/
string convertUint64ToString(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << val;
    return ss.str();
}

#endif