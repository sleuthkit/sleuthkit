/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

#pragma once

#ifdef HAVE_LIBMBEDTLS

#include <string>

using namespace std;

void writeError(string errMes);
void writeWarning(string errMes);
void writeDebug(string msg);

string convertUint64ToString(uint64_t val);
string convertUint32ToString(uint32_t val);
string convertByteArrayToString(uint8_t* bytes, size_t len);
string convertGuidToString(uint8_t* bytes);

#endif
