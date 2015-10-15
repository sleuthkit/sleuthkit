/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2015 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 *
 *  This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 *  See https://github.com/williballenthin/Rejistry for the original Java version.
 */

/**
 * \file SubkeyListRecord.cpp
 *
 */

// Local includes
#include "SubkeyListRecord.h"
#include "RejistryException.h"
#include "NKRecord.h"

namespace Rejistry {

    uint16_t SubkeyListRecord::getListLength() const {
        return getWord(LIST_LENGTH_OFFSET);
    }

    NKRecord * SubkeyListRecord::getSubkey(const std::wstring& name) const {
        NKRecord::NKRecordPtr foundRecord = NULL;

        NKRecord::NKRecordPtrList subKeys = getSubkeys();
        NKRecord::NKRecordPtrList::iterator nkIter = subKeys.begin();
        for (; nkIter != subKeys.end(); ++nkIter) {
            if (_wcsicmp(name.c_str(), (*nkIter)->getName().c_str()) == 0) {
                // Create a copy of the record to return as the records
                // in the list will be deleted.
                foundRecord = new NKRecord(*(*nkIter));
                break;
            }
        }

        // Free the list of records.
        for (nkIter = subKeys.begin(); nkIter != subKeys.end(); ++nkIter) {
            delete *nkIter;
        }

        if (foundRecord == NULL) {
            throw NoSuchElementException("Failed to find subkey.");
        }

        return foundRecord;
    }

};
