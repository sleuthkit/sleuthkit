/*
 *
 * The Sleuth Kit
 *
 * Copyright 2013-2015 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 * See https://github.com/williballenthin/Rejistry for the original Java version.
 */

/**
 * \file DirectSubkeyListRecord.h
 *
 */
#ifndef _REJISTRY_DIRECTSUBKEYLISTRECORD_H
#define _REJISTRY_DIRECTSUBKEYLISTRECORD_H

#include <cstdint>
#include <string>
#include <list>

// Local includes
#include "SubkeyListRecord.h"

namespace Rejistry {

    /**
     *
     */
    class DirectSubkeyListRecord : public SubkeyListRecord {
    public:
        DirectSubkeyListRecord(RegistryByteBuffer * buf, uint32_t offset, uint32_t itemSize) : SubkeyListRecord(buf, offset) {
            _itemSize = itemSize;
        }
        
        virtual ~DirectSubkeyListRecord() {}
    
        virtual std::vector<NKRecord *> getSubkeys() const;

    private:
        static const uint16_t LIST_START_OFFSET = 0x04;

        uint32_t _itemSize;

    protected:
        DirectSubkeyListRecord() {};
        DirectSubkeyListRecord(const DirectSubkeyListRecord &);
        DirectSubkeyListRecord& operator=(const DirectSubkeyListRecord &);
    };
};

#endif
