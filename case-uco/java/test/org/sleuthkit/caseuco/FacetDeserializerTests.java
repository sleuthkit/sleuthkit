/*
 * Sleuth Kit CASE JSON LD Support
 *
 * Copyright 2021 Basis Technology Corp.
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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.Assert;

import org.junit.Test;
import org.sleuthkit.datamodel.TskData;

/**
 * Tests for deserializing facets.
 */
public class FacetDeserializerTests {

    private static final Logger logger = Logger.getLogger(FacetDeserializerTests.class.getName());

    /**
     * Parses facets json string into a list of facets.
     * @param facetsListJson The json string.
     * @return The list of facets.
     * @throws JsonParseException 
     */
    private static List<Facet> parseFacets(String facetsListJson) throws JsonParseException {
        GsonBuilder gb = new GsonBuilder();
        gb.registerTypeAdapter(Facet.class, new FacetDeserializer());
        Gson gson = gb.create();
        Type traceList = new TypeToken<ArrayList<Facet>>() {
        }.getType();
        return gson.fromJson(facetsListJson, traceList);
    }

    @Test
    public void testExpectFacetJsonObject() {
        try {
            parseFacets("[\"test1\", 1, 2]");
            Assert.fail("Expected exception when parsing facets that are not objects");
        } catch (JsonParseException ex) {
            Assert.assertNotNull(ex.getMessage());
            logger.log(Level.INFO, "Received exception of: " + ex.getMessage());
        }
    }

    @Test
    public void testExpectFacetType() {
        try {
            parseFacets("[{\"@type\": \"NonsenseType\", \"@id\": \"ItemId\" }]");
            Assert.fail("Expected exception when parsing facets that are not objects");
        } catch (JsonParseException ex) {
            Assert.assertNotNull(ex.getMessage());
            logger.log(Level.INFO, "Received exception of: " + ex.getMessage());
        }
    }

    @Test
    public void testFacetDeserialization() throws JsonParseException {
        long clusterSize = 512;
        long createdTime = 946684800;
        long modifiedTime = 946684801;
        String description = "A file system";
        String id = "The id";
        String name = "The name";
        String tag = "The tag";
        TskData.TSK_FS_TYPE_ENUM fsType = TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_EXT4;

        UcoObject fileSystem = new FileSystem()
                .setCluserSize(clusterSize)
                .setFileSystemType(fsType)
                .setCreatedTime(createdTime)
                .setDescription(description)
                .setId(id)
                .setModifiedTime(modifiedTime)
                .setName(name)
                .setTag(tag);

        String gsonStr = new Gson().toJson(Arrays.asList(fileSystem));
        logger.log(Level.INFO, "Json string of: " + gsonStr);

        List<Facet> facets = parseFacets(gsonStr);
        Assert.assertEquals(1, facets.size());
        Assert.assertTrue(facets.get(0) instanceof FileSystem);

        FileSystem deserialized = (FileSystem) facets.get(0);
        Assert.assertEquals((Long) clusterSize, deserialized.getCluserSize());
        Assert.assertEquals(createdTime, OffsetDateTime.parse(deserialized.getCreatedTime()).toEpochSecond());
        Assert.assertEquals(modifiedTime, OffsetDateTime.parse(deserialized.getModifiedTime()).toEpochSecond());

        Assert.assertEquals(description, deserialized.getDescription());
        Assert.assertEquals(id, deserialized.getId());
        Assert.assertEquals(name, deserialized.getName());
        Assert.assertEquals(tag, deserialized.getTag());

        Assert.assertEquals(deserialized.getFileSystemType().getTskType(), fsType);
    }
    
    @Test
    public void testTraceDeserialization() throws JsonParseException {
        long clusterSize = 4096;
        long createdTime = 946684802;
        long modifiedTime = 946684803;
        String description = "A file system 2";
        String id = "The id 2";
        String name = "The name 2";
        String tag = "The tag 2";
        TskData.TSK_FS_TYPE_ENUM fsType = TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_EXT4;

        FileSystem fileSystem = (FileSystem) new FileSystem()
                .setCluserSize(clusterSize)
                .setFileSystemType(fsType)
                .setCreatedTime(createdTime)
                .setDescription(description)
                .setId(id)
                .setModifiedTime(modifiedTime)
                .setName(name)
                .setTag(tag);

        String traceUuid = "uuid";
        long traceCreateTime = 946684802;
        long traceModifiedTime = 946684803;
        String traceDescription = "A file system 2";
        String traceId = "The id 2";
        String traceName = "The name 2";
        String traceTag = "The tag 2";
        UcoObject trace = new Trace(traceUuid)
                .addBundle(fileSystem)
                .setCreatedTime(traceCreateTime)
                .setDescription(traceDescription)
                .setId(traceId)
                .setModifiedTime(traceModifiedTime)
                .setName(traceName)
                .setTag(traceTag);
        
        String gsonStr = new Gson().toJson(trace);
        logger.log(Level.INFO, "Json string of: " + gsonStr);

        Trace deserializedTrace = new GsonBuilder()
                .registerTypeAdapter(Facet.class, new FacetDeserializer())
                .create()
                .fromJson(gsonStr, Trace.class);
        
        Assert.assertEquals(traceCreateTime, OffsetDateTime.parse(deserializedTrace.getCreatedTime()).toEpochSecond());
        Assert.assertEquals(traceModifiedTime, OffsetDateTime.parse(deserializedTrace.getModifiedTime()).toEpochSecond());

        Assert.assertEquals(traceDescription, deserializedTrace.getDescription());
        Assert.assertEquals(traceId, deserializedTrace.getId());
        Assert.assertEquals(traceName, deserializedTrace.getName());
        Assert.assertEquals(traceTag, deserializedTrace.getTag());

        List<Facet> facets = deserializedTrace.getHasPropertyBundle();
        
        Assert.assertEquals(1, facets.size());
        Assert.assertTrue(facets.get(0) instanceof FileSystem);

        FileSystem deserialized = (FileSystem) facets.get(0);
        Assert.assertEquals((Long) clusterSize, deserialized.getCluserSize());
        Assert.assertEquals(createdTime, OffsetDateTime.parse(deserialized.getCreatedTime()).toEpochSecond());
        Assert.assertEquals(modifiedTime, OffsetDateTime.parse(deserialized.getModifiedTime()).toEpochSecond());

        Assert.assertEquals(description, deserialized.getDescription());
        Assert.assertEquals(id, deserialized.getId());
        Assert.assertEquals(name, deserialized.getName());
        Assert.assertEquals(tag, deserialized.getTag());

        Assert.assertEquals(deserialized.getFileSystemType().getTskType(), fsType);
    }
}
