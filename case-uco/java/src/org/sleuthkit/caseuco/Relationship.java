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
 * This class definition mirrors the core Relationship object described in the
 * UCO ontology.
 */
class Relationship extends UcoObject {

    @SerializedName("core:source")
    private String source;

    @SerializedName("core:target")
    private String target;
    
    @SerializedName("core:kindOfRelationship")
    private String kindOfRelationship;
    
    @SerializedName("core:isDirectional")
    private Boolean isDirectional;

    Relationship(String id) {
        super(id, UcoObject.UCO_CORE + Relationship.class.getSimpleName());
    }

    Relationship setSource(String source) {
        this.source = source;
        return this;
    }

    Relationship setTarget(String target) {
        this.target = target;
        return this;
    }
    
    Relationship setKindOfRelationship(String kindOfRelationship) {
        this.kindOfRelationship = kindOfRelationship;
        return this;
    }
    
    Relationship isDirectional(boolean isDirectional) {
        this.isDirectional = isDirectional;
        return this;
    }

    String getSource() {
        return source;
    }

    String getTarget() {
        return target;
    }

    String getKindOfRelationship() {
        return kindOfRelationship;
    }

    Boolean getIsDirectional() {
        return isDirectional;
    }
}
