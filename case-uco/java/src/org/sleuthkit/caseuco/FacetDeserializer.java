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

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import java.lang.reflect.Type;

/**
 * A Gson deserializer for facets that dynamically converts to POJO based on @type.
 * The @type name must exactly match the name of the POJO.
 */
class FacetDeserializer implements JsonDeserializer<Facet> {
    private static final String BASE_PACKAGE = "org.sleuthkit.caseuco";
    
    @Override
    public Facet deserialize(JsonElement je, Type type, JsonDeserializationContext jdc) throws JsonParseException {
        if (!(je instanceof JsonObject)) {
            throw new JsonParseException("Expected a json object for " + je);
        }
        
        JsonObject jObj = (JsonObject) je;
        JsonElement jsonId = jObj.get("@type");
        if (jsonId == null) {
            throw new JsonParseException("Expected non-null @type value");
        }
        
        String id = jsonId.getAsString();
        String className = BASE_PACKAGE + "." + id;
        Class<?> deserializationClass;
        try {
            deserializationClass = Class.forName(className);
        } catch (ClassNotFoundException ex) {
            throw new JsonParseException("Expected class to exist: " + className, ex);
        }
        
        return jdc.deserialize(jObj, deserializationClass);
    }
}