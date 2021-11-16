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
 * This class definition mirrors the OperatingSystemFacet observable described in the
 UCO ontology.
 */
class OperatingSystemFacet extends Facet {

    @SerializedName("observable:installDate")
    private String installDate;

    @SerializedName("observable:version")
    private String version;

    OperatingSystemFacet() {
        super(UcoObject.UCO_OBSERV + OperatingSystemFacet.class.getSimpleName());
    }

    OperatingSystemFacet setInstallDate(Long installDate) {
        if (installDate != null) {
            this.installDate = Instant.ofEpochSecond(installDate).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    OperatingSystemFacet setVersion(String version) {
        this.version = version;
        return this;
    }

    String getInstallDate() {
        return installDate;
    }

    String getVersion() {
        return version;
    }
}
