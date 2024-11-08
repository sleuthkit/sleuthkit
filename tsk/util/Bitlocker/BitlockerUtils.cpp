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


/**
* Convert the given bytes to the GUID string we would expect to see in the recovery key file.
*
* @param bytes  The GUID in bytes. Expected to have length 16.
*
* @return GUID string
*/
string convertGuidToString(uint8_t* bytes) {

    struct BITLOCKER_GUID {
        uint32_t data1;
        uint16_t data2;
        uint16_t data3;
        BYTE*  data4;
    } guidStruct;

    guidStruct.data1 = tsk_getu32(TSK_LIT_ENDIAN, &bytes[0]);
    guidStruct.data2 = tsk_getu16(TSK_LIT_ENDIAN, &bytes[4]);
    guidStruct.data3 = tsk_getu16(TSK_LIT_ENDIAN, &bytes[6]);
    guidStruct.data4 = &bytes[8];

    stringstream ss;
    ss << std::uppercase << std::hex;
    ss << std::setw(8) << std::setfill('0') << guidStruct.data1 << '-';

    ss << std::setw(4) << std::setfill('0') << guidStruct.data2 << '-';

    ss << std::setw(4) << std::setfill('0') << guidStruct.data3 << '-';

    ss << std::setw(2) << std::setfill('0') << static_cast<short>(guidStruct.data4[0])
        << std::setw(2) << std::setfill('0') << static_cast<short>(guidStruct.data4[1])
        << '-'
        << std::setw(2) << std::setfill('0') << static_cast<short>(guidStruct.data4[2])
        << std::setw(2) << std::setfill('0') << static_cast<short>(guidStruct.data4[3])
        << std::setw(2) << std::setfill('0') << static_cast<short>(guidStruct.data4[4])
        << std::setw(2) << std::setfill('0') << static_cast<short>(guidStruct.data4[5])
        << std::setw(2) << std::setfill('0') << static_cast<short>(guidStruct.data4[6])
        << std::setw(2) << std::setfill('0') << static_cast<short>(guidStruct.data4[7]);
    ss << std::nouppercase;
    return ss.str();
}

#endif