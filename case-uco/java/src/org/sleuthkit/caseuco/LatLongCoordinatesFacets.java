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
 * This class definition mirrors the LatLongCoordinatesFacets observable described in
 the UCO ontology.
 */
class LatLongCoordinatesFacets extends Facet {

    @SerializedName("location:altitude")
    private Double altitude;

    @SerializedName("location:latitude")
    private Double latitude;

    @SerializedName("location:longitude")
    private Double longitude;

    LatLongCoordinatesFacets() {
        super(UcoObject.UCO_LOCATION + LatLongCoordinatesFacets.class.getSimpleName());
    }

    LatLongCoordinatesFacets setAltitude(Double altitude) {
        this.altitude = altitude;
        return this;
    }

    LatLongCoordinatesFacets setLatitude(Double latitude) {
        this.latitude = latitude;
        return this;
    }

    LatLongCoordinatesFacets setLongitude(Double longitude) {
        this.longitude = longitude;
        return this;
    }

    Double getAltitude() {
        return altitude;
    }

    Double getLatitude() {
        return latitude;
    }

    Double getLongitude() {
        return longitude;
    }
}
