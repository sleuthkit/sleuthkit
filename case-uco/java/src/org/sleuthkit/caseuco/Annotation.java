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
import java.util.ArrayList;
import java.util.List;

/**
 * This class definition mirrors the core Annotation object described in the UCO
 * ontology.
 */
class Annotation extends UcoObject {

    @SerializedName("tag")
    private final List<String> tags;

    private final List<String> object;

    Annotation(String uuid) {
        super(uuid, "Annotation");
        tags = new ArrayList<>();
        object = new ArrayList<>();
    }

    Annotation addTag(String tag) {
        this.tags.add(tag);
        return this;
    }

    Annotation addObject(String object) {
        this.object.add(object);
        return this;
    }
}
