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

/**
 * This class definition mirrors the ApplicationFacet observable described in the UCO
 ontology.
 */
class ApplicationFacet extends Facet {

    @SerializedName("observable:applicationIdentifier")    
    private String applicationIdentifier;

    @SerializedName("observable:operatingSystem")
    private String operatingSystem;

    @SerializedName("observable:numberOfLaunches")
    private Integer numberOfLaunches;

    @SerializedName("observable:version")
    private String version;

    ApplicationFacet() {
        super(UcoObject.UCO_OBSERV + ApplicationFacet.class.getSimpleName());
    }

    ApplicationFacet setApplicationIdentifier(String applicationIdentifier) {
        this.applicationIdentifier = applicationIdentifier;
        return this;
    }

    ApplicationFacet setOperatingSystem(ObservableObject operatingSystem) {
        this.operatingSystem = operatingSystem.getId();
        return this;
    }

    ApplicationFacet setNumberOfLaunches(Integer numberOfLaunches) {
        this.numberOfLaunches = numberOfLaunches;
        return this;
    }

    ApplicationFacet setVersion(String version) {
        this.version = version;
        return this;
    }

    String getApplicationIdentifier() {
        return applicationIdentifier;
    }

    String getOperatingSystem() {
        return operatingSystem;
    }

    Integer getNumberOfLaunches() {
        return numberOfLaunches;
    }

    String getVersion() {
        return version;
    }
}
