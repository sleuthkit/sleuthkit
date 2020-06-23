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
package org.sleuthkit.uco.observable;

import java.time.Instant;
import java.time.ZoneOffset;
import org.sleuthkit.uco.core.Facet;
import org.sleuthkit.uco.location.Location;

public class CalendarEntry extends Facet {
    
    private String eventType;
    
    private String startTime;
    
    private String endTime;
    
    private String location;
    
    public CalendarEntry() {
        super(CalendarEntry.class.getSimpleName());
    }
    
    public CalendarEntry setEventType(String eventType) {
        this.eventType = eventType;
        return this;
    }
    
    public CalendarEntry setLocation(Location location) {
        this.location = location.getId();
        return this;
    }
    
    public CalendarEntry setEndTime(Long endTime) {
        if (endTime != null) {
            this.endTime = Instant.ofEpochSecond(endTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }
    
    public CalendarEntry setStartTime(Long startTime) {
        if (startTime != null) {
            this.startTime = Instant.ofEpochSecond(startTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }
}
