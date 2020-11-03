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
 * This class definition mirrors the LatLongCoordinates observable described in
 * the UCO ontology.
 */
class LatLongCoordinates extends Facet {

    private Double altitude;

    private Double latitude;

    private Double longitude;

    LatLongCoordinates() {
        super(LatLongCoordinates.class.getSimpleName());
    }

    LatLongCoordinates setAltitude(Double altitude) {
        this.altitude = altitude;
        return this;
    }

    LatLongCoordinates setLatitude(Double latitude) {
        this.latitude = latitude;
        return this;
    }

    LatLongCoordinates setLongitude(Double longitude) {
        this.longitude = longitude;
        return this;
    }
}
