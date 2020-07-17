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

import com.google.gson.annotations.SerializedName;
import java.time.Instant;
import java.time.ZoneOffset;

/**
 * Base class for all CASE/UCO constructs.
 */
abstract class UcoObject {

    @SerializedName("@id")
    private String id;

    @SerializedName("@type")
    private final String type;

    private String createdTime;
    
    private String modifiedTime;

    private String description;

    private String name;

    private String tag;

    UcoObject(String id, String type) {
        this.id = id;
        this.type = type;
    }

    String getId() {
        return this.id;
    }

    UcoObject setCreatedTime(Long createdTime) {
        if (createdTime != null) {
            this.createdTime = Instant.ofEpochSecond(createdTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    UcoObject setModifiedTime(Long modifiedTime) {
        if (modifiedTime != null) {
            this.modifiedTime = Instant.ofEpochSecond(modifiedTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    UcoObject setId(String id) {
        this.id = id;
        return this;
    }

    UcoObject setDescription(String description) {
        this.description = description;
        return this;
    }

    UcoObject setName(String name) {
        this.name = name;
        return this;
    }

    UcoObject setTag(String tag) {
        this.tag = tag;
        return this;
    }
}
