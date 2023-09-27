/*
 * Sleuth Kit CASE JSON LD Support
 *
 * Copyright 2020-2021 Basis Technology Corp.
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

import java.time.Instant;
import java.time.ZoneOffset;

/**
 * This class definition mirrors the DigitalAccount observable described in the
 * UCO ontology.
 */
class DigitalAccount extends Facet {

    private String displayName;

    private String lastLoginTime;

    DigitalAccount() {
        super(DigitalAccount.class.getSimpleName());
    }

    DigitalAccount setDisplayName(String displayName) {
        this.displayName = displayName;
        return this;
    }

    DigitalAccount setLastLoginTime(Long time) {
        if (time != null) {
            this.lastLoginTime = Instant.ofEpochSecond(time).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    String getDisplayName() {
        return displayName;
    }

    String getLastLoginTime() {
        return lastLoginTime;
    }
}
