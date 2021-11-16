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

import com.google.gson.annotations.SerializedName;
import java.time.Instant;
import java.time.ZoneOffset;

/**
 * This class definition mirrors the DigitalAccountFacet observable described in the
 UCO ontology.
 */
class DigitalAccountFacet extends Facet {

    @SerializedName("observable:displayName")
    private String displayName;

    @SerializedName("observable:lastLoginTime")
    private String lastLoginTime;

    DigitalAccountFacet() {
        super(UcoObject.UCO_OBSERV + DigitalAccountFacet.class.getSimpleName());
    }

    DigitalAccountFacet setDisplayName(String displayName) {
        this.displayName = displayName;
        return this;
    }

    DigitalAccountFacet setLastLoginTime(Long time) {
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
