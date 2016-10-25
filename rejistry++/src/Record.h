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
 * \file Record.h
 *
 */
#ifndef _REJISTRY_RECORD_H
#define _REJISTRY_RECORD_H

#include <string>

// Local includes
#include "BinaryBlock.h"

namespace Rejistry {

    /**
     * Common base class for structures that are found within Cells.
     */
    class Record : public BinaryBlock {
    public:
        Record(RegistryByteBuffer * buf, uint32_t offset) : BinaryBlock(*buf, offset) { }
        
        virtual ~Record() {}
    
        /**
         * Get the magic bytes that determine the Record's type.
         * @returns A 2 character string that is the magic record header.
         * @throws RegistryParseException.
         */
        std::string getMagic() const;

    private:
        static const uint8_t MAGIC_OFFSET = 0x0;

    protected:
        Record() {};
        Record(const Record &) {};
        Record& operator=(const Record &);
    };

};

#endif
