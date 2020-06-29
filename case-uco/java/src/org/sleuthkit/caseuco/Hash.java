/*
 * Sleuth Kit CASE JSON LD Support
 *
 * Copyright 2020 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.caseuco;

/**
 * This class definition mirrors the Hash type described in the UCO ontology.
 */
class Hash extends UcoObject {

    private HashMethod hashMethod;

    private final String hashValue;

    Hash(String hashValue) {
        this(null, hashValue);
    }

    Hash(String id, String hashValue) {
        super(id, "Hash");
        this.hashValue = hashValue;
    }

    Hash setHashMethod(HashMethod method) {
        this.hashMethod = method;
        return this;
    }

    /**
     * Describes the type of hash method that is represented by this Hash
     * instance.
     */
    enum HashMethod {
        MD5;
    }
}
