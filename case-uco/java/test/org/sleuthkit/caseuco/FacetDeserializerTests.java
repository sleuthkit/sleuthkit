/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
    public void testDeserialization() throws JsonParseException {
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
}
