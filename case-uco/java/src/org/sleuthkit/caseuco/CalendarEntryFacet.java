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
 * This class definition mirrors the CalendarEntryFacet observable described in the
 UCO ontology.
 */
class CalendarEntryFacet extends Facet {

   @SerializedName("observable:eventType")
    private String eventType;

   @SerializedName("observable:startTime")
    private String startTime;

   @SerializedName("observable:endTime")
    private String endTime;

   @SerializedName("observable:endTime")
    private String location;

    CalendarEntryFacet() {
        super(UcoObject.UCO_OBSERV + CalendarEntryFacet.class.getSimpleName());
    }

    CalendarEntryFacet setEventType(String eventType) {
        this.eventType = eventType;
        return this;
    }

    CalendarEntryFacet setLocation(Location location) {
        this.location = location.getId();
        return this;
    }

    CalendarEntryFacet setEndTime(Long endTime) {
        if (endTime != null) {
            this.endTime = Instant.ofEpochSecond(endTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    CalendarEntryFacet setStartTime(Long startTime) {
        if (startTime != null) {
            this.startTime = Instant.ofEpochSecond(startTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    String getEventType() {
        return eventType;
    }

    String getStartTime() {
        return startTime;
    }

    String getEndTime() {
        return endTime;
    }

    String getLocation() {
        return location;
    }
}
