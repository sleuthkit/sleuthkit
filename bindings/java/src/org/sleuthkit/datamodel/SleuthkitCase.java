/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011 Basis Technology Corp.
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
package org.sleuthkit.datamodel;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import org.sleuthkit.datamodel.TskData.ObjectType;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.SleuthkitJNI.CaseDbHandle.AddImageProcess;
import org.sleuthkit.datamodel.TskData.FileKnown;
import org.sleuthkit.datamodel.TskData.TSK_DB_FILES_TYPE_ENUM;
import org.sleuthkit.datamodel.TskData.TSK_FS_META_TYPE_ENUM;

/**
 * Represents the case database and abstracts out the most commonly used
 * database operations.
 * 
 * Also provides case database-level lock that protect access to the database resource.
 * The lock is available outside of the class to synchronize certain actions (such as addition of an image)
 * with concurrent database writes, for database implementations (such as SQLite) that might need it.
 */
public class SleuthkitCase {

    private String dbPath;
    private volatile SleuthkitJNI.CaseDbHandle caseHandle;
    private volatile Connection con;
    private ResultSetHelper rsHelper = new ResultSetHelper(this);
    private int artifactIDcounter = 1001;
    private int attributeIDcounter = 1001;
    //database lock
    private static final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock(true); //use fairness policy
    private static final Lock caseDbLock = rwLock.writeLock(); //use the same lock for reads and writes

    /**
     * constructor (private) - client uses openCase() and newCase() instead
     * @param dbPath path to the database
	 * @param caseHandle handle to the case database API
     * @throws SQLException thrown if SQL error occurred
     * @throws ClassNotFoundException thrown if database driver could not be loaded
	 * @throws TskCoreException thrown if critical error occurred within TSK case
     */
    private SleuthkitCase(String dbPath, SleuthkitJNI.CaseDbHandle caseHandle) throws SQLException, ClassNotFoundException, TskCoreException {
        Class.forName("org.sqlite.JDBC");
        this.dbPath = dbPath;
        this.caseHandle = caseHandle;
        con = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        configureDB();
        initBlackboardTypes();
    }

    private void configureDB() throws TskCoreException {
        try {
            //this should match SleuthkitJNI db setup
            final Statement statement = con.createStatement();
            //reduce i/o operations, we have no OS crash recovery anyway
            statement.execute("PRAGMA synchronous = OFF;");
            statement.close();
        } catch (SQLException e) {
            throw new TskCoreException("Couldn't configure the database connection", e);
        }
    }

    /**
     * Lock to protect against concurrent write accesses to case database
     * Should be utilized by all db code where underlying storage supports max. 1 concurrent writer
     * MUST always call dbWriteUnLock() as early as possible, in the same thread where dbWriteLock() was called
     */
    public static void dbWriteLock() {
        //Logger.getLogger("LOCK").log(Level.INFO, "Locking " + rwLock.toString());
        caseDbLock.lock();
    }

    /**
     * Release previously acquired write lock acquired in this thread using dbWriteLock()
     */
    public static void dbWriteUnlock() {
        //Logger.getLogger("LOCK").log(Level.INFO, "UNLocking " + rwLock.toString());
        caseDbLock.unlock();
    }

    /**
     * Lock to protect against read accesses to case database while it's being written
     * Should be utilized by all db code where underlying storage does not support reads while in write transaction
     * MUST always call dbReadUnLock() as early as possible, in the same thread where dbReadLock() was called
     */
    static void dbReadLock() {
        caseDbLock.lock();
    }

    /**
     * Release previously acquired read lock acquired in this thread using dbReadLock()
     */
    static void dbReadUnlock() {
        caseDbLock.unlock();
    }

    /**
     * Open an existing case
     * @param dbPath Path to SQLite database.
     * @return Case object
     */
    public static SleuthkitCase openCase(String dbPath) throws TskCoreException {
        SleuthkitCase.dbWriteLock();
        SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.openCaseDb(dbPath);
        try {
            return new SleuthkitCase(dbPath, caseHandle);
        } catch (SQLException ex) {
            throw new TskCoreException("Couldn't open case at " + dbPath, ex);
        } catch (ClassNotFoundException ex) {
            throw new TskCoreException("Couldn't open case at " + dbPath, ex);
        } finally {
            SleuthkitCase.dbWriteUnlock();
        }
    }

    /**
     * Create a new case
     * @param dbPath Path to where SQlite database should be created.
     * @return Case object
     */
    public static SleuthkitCase newCase(String dbPath) throws TskCoreException {
        SleuthkitCase.dbWriteLock();
        SleuthkitJNI.CaseDbHandle caseHandle = SleuthkitJNI.newCaseDb(dbPath);
        try {
            return new SleuthkitCase(dbPath, caseHandle);
        } catch (SQLException ex) {
            throw new TskCoreException("Couldn't open case at " + dbPath, ex);
        } catch (ClassNotFoundException ex) {
            throw new TskCoreException("Couldn't open case at " + dbPath, ex);
        } finally {
            SleuthkitCase.dbWriteUnlock();
        }

    }

    private void initBlackboardTypes() throws SQLException, TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            for (ARTIFACT_TYPE type : ARTIFACT_TYPE.values()) {
                ResultSet rs = s.executeQuery("SELECT * from blackboard_artifact_types WHERE artifact_type_id = '" + type.getTypeID() + "'");
                if (!rs.next()) {
                    this.addBuiltInArtifactType(type);
                }
                rs.close();
            }
            for (ATTRIBUTE_TYPE type : ATTRIBUTE_TYPE.values()) {
                ResultSet rs = s.executeQuery("SELECT * from blackboard_attribute_types WHERE attribute_type_id = '" + type.getTypeID() + "'");
                if (!rs.next()) {
                    this.addBuiltInAttrType(type);
                }
                rs.close();
            }
            s.close();
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Start process of adding an image to the case.
     * Adding an image is a multi-step process and this returns
     * an object that allows it to happen.
     * @param timezone TZ timezone string to use for ingest of image.
	 * @param processUnallocSpace set to true if to process unallocated space on the image
     * @param noFatFsOrphans true if to skip processing orphans on FAT filesystems
     * @return object to start ingest
     */
    public AddImageProcess makeAddImageProcess(String timezone, boolean processUnallocSpace, boolean noFatFsOrphans) {
        return this.caseHandle.initAddImageProcess(timezone, processUnallocSpace, noFatFsOrphans);
    }

    /**
     * Set the NSRL database
     * @param path The path to the database
     * @return a handle for that database
     */
    public int setNSRLDatabase(String path) throws TskCoreException {
        return this.caseHandle.setNSRLDatabase(path);
    }

    /**
     * Add the known bad database
     * @param path The path to the database
     * @return a handle for that database
     */
    public int addKnownBadDatabase(String path) throws TskCoreException {
        return this.caseHandle.addKnownBadDatabase(path);
    }

	/**
	 * Reset currently used lookup databases on that case object
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
	 */
    public void clearLookupDatabases() throws TskCoreException {
        this.caseHandle.clearLookupDatabases();
    }

    /**
     * Get the list of root objects, meaning image files or local files.
     * @return list of content objects.
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public List<Content> getRootObjects() throws TskCoreException {
        Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();
        dbReadLock();
        try {

            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("select obj_id, type from tsk_objects "
                    + "where par_obj_id is NULL");

            while (rs.next()) {
                infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type"))));
            }
            rs.close();
            s.close();


            List<Content> rootObjs = new ArrayList<Content>();

            for (ObjectInfo i : infos) {
                if (i.type == ObjectType.IMG) {
                    rootObjs.add(getImageById(i.id));
                } else {
                    throw new TskCoreException("Parentless object has wrong type to be a root: " + i.type);
                }
            }

            return rootObjs;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting root objects.", ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Get all blackboard artifacts of a given type
     * @param artifactTypeID artifact type id (must exist in database)
     * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID) throws TskCoreException {
        String artifactTypeName = this.getArtifactTypeString(artifactTypeID);
        dbReadLock();
        try {
            ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("SELECT artifact_id, obj_id FROM blackboard_artifacts WHERE artifact_type_id = " + artifactTypeID);

            while (rs.next()) {
                artifacts.add(new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2),
                        artifactTypeID, artifactTypeName, ARTIFACT_TYPE.fromID(artifactTypeID).getDisplayName()));
            }
            rs.close();
            s.close();
            return artifacts;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
        } finally {
            dbReadUnlock();
        }

    }

    /**
     * Get all blackboard artifact types
     * @return list of blackboard artifact types
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardArtifact.ARTIFACT_TYPE> getBlackboardArtifactTypes() throws TskCoreException {
        dbReadLock();
        try {
            ArrayList<BlackboardArtifact.ARTIFACT_TYPE> artifact_types = new ArrayList<BlackboardArtifact.ARTIFACT_TYPE>();
            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("SELECT artifact_type_id FROM blackboard_artifact_types");

            while (rs.next()) {
                artifact_types.add(BlackboardArtifact.ARTIFACT_TYPE.fromID(rs.getInt(1)));
            }
            rs.close();
            s.close();
            return artifact_types;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting artifact types. " + ex.getMessage(), ex);
        } finally {
            dbReadUnlock();
        }

    }

    /**
     * Helper method to get all artifacts matching the type id name and object id
     * @param artifactTypeID artifact type id
     * @param artifactTypeName artifact type name
     * @param obj_id associated object id
     * @return list of blackboard artifacts
     * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    private ArrayList<BlackboardArtifact> getArtifactsHelper(int artifactTypeID, String artifactTypeName, long obj_id) throws TskCoreException {
        dbReadLock();
        try {
            ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("SELECT artifact_id FROM blackboard_artifacts WHERE obj_id = " + obj_id + " AND artifact_type_id = " + artifactTypeID);

            while (rs.next()) {
                artifacts.add(new BlackboardArtifact(this, rs.getLong(1), obj_id, artifactTypeID, artifactTypeName, this.getArtifactTypeDisplayName(artifactTypeID)));
            }
            rs.close();
            s.close();
            return artifacts;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * helper method to get all artifacts matching the type id name
     * @param artifactTypeID artifact type id
     * @param artifactTypeName artifact type name
     * @return list of blackboard artifacts
     * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    private ArrayList<BlackboardArtifact> getArtifactsHelper(int artifactTypeID, String artifactTypeName) throws TskCoreException {
        dbReadLock();
        try {
            ArrayList<BlackboardArtifact> artifacts = new ArrayList<BlackboardArtifact>();
            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("SELECT artifact_id, obj_id FROM blackboard_artifacts WHERE artifact_type_id = " + artifactTypeID);

            while (rs.next()) {
                artifacts.add(new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2), artifactTypeID, artifactTypeName, this.getArtifactTypeDisplayName(artifactTypeID)));
            }
            rs.close();
            s.close();
            return artifacts;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Get all blackboard artifacts of a given type for the given object id
     * @param artifactTypeName artifact type name
     * @param obj_id object id
     * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName, long obj_id) throws TskCoreException {
        int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
        return getArtifactsHelper(artifactTypeID, artifactTypeName, obj_id);
    }

    /**
     * Get all blackboard artifacts of a given type for the given object id
     * @param artifactTypeID artifact type id (must exist in database)
     * @param obj_id object id
     * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardArtifact> getBlackboardArtifacts(int artifactTypeID, long obj_id) throws TskCoreException {
        String artifactTypeName = this.getArtifactTypeString(artifactTypeID);

        return getArtifactsHelper(artifactTypeID, artifactTypeName, obj_id);
    }

    /**
     * Get all blackboard artifacts of a given type for the given object id
	 * 
     * @param artifactType artifact type enum
     * @param obj_id object id
     * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType, long obj_id) throws TskCoreException {
        return getArtifactsHelper(artifactType.getTypeID(), artifactType.getLabel(), obj_id);
    }

    /**
     * Get all blackboard artifacts of a given type
	 * 
     * @param artifactTypeName artifact type name
     * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardArtifact> getBlackboardArtifacts(String artifactTypeName) throws TskCoreException {
        int artifactTypeID = this.getArtifactTypeID(artifactTypeName);
        return getArtifactsHelper(artifactTypeID, artifactTypeName);
    }

    /**
     * Get all blackboard artifacts of a given type 
	 * 
     * @param artifactType artifact type enum
     * @return list of blackboard artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardArtifact> getBlackboardArtifacts(ARTIFACT_TYPE artifactType) throws TskCoreException {
        return getArtifactsHelper(artifactType.getTypeID(), artifactType.getLabel());
    }

    /**
     * Get the blackboard artifact with the given artifact id
	 * 
     * @param artifactID artifact ID
     * @return blackboard artifact
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public BlackboardArtifact getBlackboardArtifact(long artifactID) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs;

            rs = s.executeQuery("SELECT obj_id, artifact_type_id FROM blackboard_artifacts WHERE artifact_id = " + artifactID);
            long obj_id = rs.getLong(1);
            int artifact_type_id = rs.getInt(2);

            rs.close();
            s.close();
            return new BlackboardArtifact(this, artifactID, obj_id, artifact_type_id, this.getArtifactTypeString(artifact_type_id), this.getArtifactTypeDisplayName(artifact_type_id));

        } catch (SQLException ex) {
            throw new TskCoreException("Error getting a blackboard artifact. " + ex.getMessage(), ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Add a blackboard attribute. All information for the attribute should be in the given attribute
	 * 
     * @param attr a blackboard attribute. All necessary information should be filled in.
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public void addBlackboardAttribute(BlackboardAttribute attr) throws TskCoreException {
        dbWriteLock();
        try {
            Statement s = con.createStatement();
            switch (attr.getValueType()) {
                case STRING:
                    s.executeUpdate("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_text) VALUES ("
                            + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", '" + escapeForBlackboard(attr.getValueString()) + "')");
                    break;
                case BYTE:
                    PreparedStatement ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_byte) VALUES ("
                            + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", ?)");
                    ps.setBytes(1, attr.getValueBytes());
                    ps.executeUpdate();
                    ps.close();
                    break;
                case INTEGER:
                    s.executeUpdate("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int32) VALUES ("
                            + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueInt() + ")");
                    break;
                case LONG:
                    s.executeUpdate("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int64) VALUES ("
                            + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueLong() + ")");
                    break;
                case DOUBLE:
                    s.executeUpdate("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_double) VALUES ("
                            + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueDouble() + ")");
                    break;
            }
            s.close();
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting or creating a blackboard artifact.", ex);
        } finally {
            dbWriteUnlock();
        }
    }

    /**
     * Add a blackboard attributes in bulk. All information for the attribute should be in the given attribute
	 * 
     * @param attributes collection of blackboard attributes. All necessary information should be filled in.
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public void addBlackboardAttributes(Collection<BlackboardAttribute> attributes) throws TskCoreException {
        dbWriteLock();
        try {
            con.setAutoCommit(false);
        } catch (SQLException ex) {
            dbWriteUnlock();
            throw new TskCoreException("Error creating transaction, no attributes created.", ex);
        }

        for (BlackboardAttribute attr : attributes) {
            PreparedStatement ps = null;
            try {
                switch (attr.getValueType()) {
                    case STRING:
                        ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_text) VALUES ("
                                + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", '" + escapeForBlackboard(attr.getValueString()) + "')");
                        break;
                    case BYTE:
                        ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_byte) VALUES ("
                                + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", ?)");
                        ps.setBytes(1, attr.getValueBytes());
                        break;
                    case INTEGER:
                        ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int32) VALUES ("
                                + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueInt() + ")");
                        break;
                    case LONG:
                        ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_int64) VALUES ("
                                + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueLong() + ")");
                        break;
                    case DOUBLE:
                        ps = con.prepareStatement("INSERT INTO blackboard_attributes (artifact_id, source, context, attribute_type_id, value_type, value_double) VALUES ("
                                + attr.getArtifactID() + ", '" + attr.getModuleName() + "', '" + attr.getContext() + "', " + attr.getAttributeTypeID() + ", " + attr.getValueType().getType() + ", " + attr.getValueDouble() + ")");
                        break;
                }
                ps.executeUpdate();
                ps.close();
            } catch (SQLException ex) {
                Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING, "Error adding attribute: " + attr.toString(), ex);
                //try to add more attributes 
            }
        }

        //commit transaction
        try {
            con.commit();
        } catch (SQLException ex) {
            throw new TskCoreException("Error committing transaction, no attributes created.", ex);
        } finally {
            try {
                con.setAutoCommit(true);
            } catch (SQLException ex) {
                throw new TskCoreException("Error setting autocommit and closing the transaction!", ex);
            } finally {
                dbWriteUnlock();
            }
        }

    }

    /**
     * add an attribute type with the given name
	 * 
     * @param attrTypeString name of the new attribute
	 * @param displayName the (non-unique) display name of the attribute type
     * @return the id of the new attribute
     * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public int addAttrType(String attrTypeString, String displayName) throws TskCoreException {
        addAttrType(attrTypeString, displayName, attributeIDcounter);
        int retval = attributeIDcounter;
        attributeIDcounter++;
        return retval;

    }

    /**
     * helper method. add an attribute type with the given name and id
	 * 
     * @param attrTypeString type name
	 * @param displayName the (non-unique) display name of the attribute type
     * @param typeID type id
     * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    private void addAttrType(String attrTypeString, String displayName, int typeID) throws TskCoreException {
        dbWriteLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("SELECT * from blackboard_attribute_types WHERE type_name = '" + attrTypeString + "'");
            if (!rs.next()) {
                s.executeUpdate("INSERT INTO blackboard_attribute_types (attribute_type_id, type_name, display_name) VALUES (" + typeID + ", '" + attrTypeString + "', '" + displayName + "')");
                rs.close();
                s.close();
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("Attribute with that name already exists");
            }
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting attribute type id.", ex);
        } finally {
            dbWriteUnlock();
        }
    }

    /**
     * Get the attribute id that corresponds to the given string. If that string does not exist
     * it will be added to the table.
	 * 
     * @param attrTypeString attribute type string
     * @return attribute id
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public int getAttrTypeID(String attrTypeString) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs;

            rs = s.executeQuery("SELECT attribute_type_id FROM blackboard_attribute_types WHERE type_name = '" + attrTypeString + "'");
            if (rs.next()) {
                int type = rs.getInt(1);
                rs.close();
                s.close();
                return type;
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("No id with that name");
            }
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting attribute type id.", ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Get the string associated with the given id. Will throw an error if that id does not exist
	 * 
     * @param attrTypeID attribute id
     * @return string associated with the given id
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public String getAttrTypeString(int attrTypeID) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs;

            rs = s.executeQuery("SELECT type_name FROM blackboard_attribute_types WHERE attribute_type_id = " + attrTypeID);
            if (rs.next()) {
                String type = rs.getString(1);
                rs.close();
                s.close();
                return type;
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("No type with that id.");
            }

        } catch (SQLException ex) {
            throw new TskCoreException("Error getting or creating a attribute type name.", ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Get the display name for the attribute with the given id. Will throw an error if that id does not exist
	 * 
     * @param attrTypeID attribute id
     * @return string associated with the given id
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public String getAttrTypeDisplayName(int attrTypeID) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs;

            rs = s.executeQuery("SELECT display_name FROM blackboard_attribute_types WHERE attribute_type_id = " + attrTypeID);
            if (rs.next()) {
                String type = rs.getString(1);
                rs.close();
                s.close();
                return type;
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("No type with that id.");
            }

        } catch (SQLException ex) {
            throw new TskCoreException("Error getting or creating a attribute type name.", ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Get artifact type id for the given string. Will throw an error if one with that
     * name does not exist.
	 * 
     * @param artifactTypeString name for an artifact type
     * @return artifact type
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    int getArtifactTypeID(String artifactTypeString) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs;

            rs = s.executeQuery("SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name = '" + artifactTypeString + "'");
            if (rs.next()) {
                int type = rs.getInt(1);
                rs.close();
                s.close();
                return type;
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("No artifact with that name exists");
            }

        } catch (SQLException ex) {
            throw new TskCoreException("Error getting artifact type id." + ex.getMessage(), ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Get artifact type name for the given string. Will throw an error if that artifact doesn't
     * exist. Use addArtifactType(...) to create a new one.
	 * 
     * @param artifactTypeID id for an artifact type
     * @return name of that artifact type
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    String getArtifactTypeString(int artifactTypeID) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs;

            rs = s.executeQuery("SELECT type_name FROM blackboard_artifact_types WHERE artifact_type_id = " + artifactTypeID);
            if (rs.next()) {
                String type = rs.getString(1);
                rs.close();
                s.close();
                return type;
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("Error: no artifact with that name in database");
            }

        } catch (SQLException ex) {
            throw new TskCoreException("Error getting artifact type id.", ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Get artifact type display name for the given string. Will throw an error if that artifact doesn't
     * exist. Use addArtifactType(...) to create a new one.
	 * 
     * @param artifactTypeID id for an artifact type
     * @return display name of that artifact type
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    String getArtifactTypeDisplayName(int artifactTypeID) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs;

            rs = s.executeQuery("SELECT display_name FROM blackboard_artifact_types WHERE artifact_type_id = " + artifactTypeID);
            if (rs.next()) {
                String type = rs.getString(1);
                rs.close();
                s.close();
                return type;
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("Error: no artifact with that name in database");
            }

        } catch (SQLException ex) {
            throw new TskCoreException("Error getting artifact type id.", ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Add an artifact type with the given name. Will return an id that can be used
     * to look that artifact type up.
	 * 
     * @param artifactTypeName System (unique) name of artifact
     * @param displayName Display (non-unique) name of artifact
     * @return ID of artifact added
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public int addArtifactType(String artifactTypeName, String displayName) throws TskCoreException {
        addArtifactType(artifactTypeName, displayName, artifactIDcounter);
        int retval = artifactIDcounter;
        artifactIDcounter++;
        return retval;
    }

    /**
     * helper method. add an artifact with the given type and id
	 * 
     * @param artifactTypeName type name
	 * @param displayName Display (non-unique) name of artifact
     * @param typeID type id
     * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    private void addArtifactType(String artifactTypeName, String displayName, int typeID) throws TskCoreException {
        dbWriteLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("SELECT * FROM blackboard_artifact_types WHERE type_name = '" + artifactTypeName + "'");
            if (!rs.next()) {
                s.executeUpdate("INSERT INTO blackboard_artifact_types (artifact_type_id, type_name, display_name) VALUES (" + typeID + " , '" + artifactTypeName + "', '" + displayName + "')");
                rs.close();
                s.close();
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("Artifact with that name already exists");
            }
        } catch (SQLException ex) {
            throw new TskCoreException("Error adding artifact type.", ex);
        } finally {
            dbWriteUnlock();
        }

    }

    /**
     * Get all attributes that match a where clause. The clause should begin with
     * "WHERE" or "JOIN". To use this method you must know the database tables
	 * 
     * @param whereClause a sqlite where clause
     * @return a list of matching attributes
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardAttribute> getMatchingAttributes(String whereClause) throws TskCoreException {
        ArrayList<BlackboardAttribute> matches = new ArrayList<BlackboardAttribute>();
        dbReadLock();
        try {
            Statement s;

            s = con.createStatement();

            ResultSet rs = s.executeQuery("Select artifact_id, source, context, attribute_type_id, value_type, "
                    + "value_byte, value_text, value_int32, value_int64, value_double FROM blackboard_attributes " + whereClause);

            while (rs.next()) {
                BlackboardAttribute attr = new BlackboardAttribute(rs.getLong("artifact_id"), rs.getInt("attribute_type_id"), rs.getString("source"), rs.getString("context"),
                        BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.fromType(rs.getInt("value_type")), rs.getInt("value_int32"), rs.getLong("value_int64"), rs.getDouble("value_double"),
                        rs.getString("value_text"), rs.getBytes("value_byte"), this);
                matches.add(attr);
            }
            rs.close();
            s.close();

            return matches;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting attributes. using this where clause: " + whereClause, ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Get all artifacts that match a where clause. The clause should begin with
     * "WHERE" or "JOIN". To use this method you must know the database tables
	 * 
     * @param whereClause a sqlite where clause
     * @return a list of matching artifacts
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    public ArrayList<BlackboardArtifact> getMatchingArtifacts(String whereClause) throws TskCoreException {
        ArrayList<BlackboardArtifact> matches = new ArrayList<BlackboardArtifact>();
        dbReadLock();
        try {
            Statement s;
            s = con.createStatement();

            ResultSet rs = s.executeQuery("Select artifact_id, obj_id, artifact_type_id FROM blackboard_artifacts " + whereClause);

            while (rs.next()) {
                BlackboardArtifact artifact = new BlackboardArtifact(this, rs.getLong(1), rs.getLong(2), rs.getInt(3), this.getArtifactTypeString(rs.getInt(3)), this.getArtifactTypeDisplayName(rs.getInt(3)));
                matches.add(artifact);
            }
            rs.close();
            s.close();
            return matches;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting attributes. using this where clause: " + whereClause, ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Add a new blackboard artifact with the given type. If that artifact type does not
     * exist an error will be thrown. The artifact typename can be looked up in the
     * returned blackboard artifact
	 * 
     * @param artifactTypeID the type the given artifact should have
	 * @param obj_id the content object id associated with this artifact
     * @return a new blackboard artifact
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    BlackboardArtifact newBlackboardArtifact(int artifactTypeID, long obj_id) throws TskCoreException {
        dbWriteLock();
        try {
            Statement s = con.createStatement();

            String artifactTypeName = this.getArtifactTypeString(artifactTypeID);
            String artifactDisplayName = this.getArtifactTypeDisplayName(artifactTypeID);

            long artifactID = -1;
            s.executeUpdate("INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_type_id) VALUES (NULL, " + obj_id + ", " + artifactTypeID + ")");
            ResultSet rs = s.executeQuery("SELECT max(artifact_id) from blackboard_artifacts WHERE obj_id = " + obj_id + " AND + artifact_type_id = " + artifactTypeID);
            artifactID = rs.getLong(1);
            rs.close();
            s.close();
            return new BlackboardArtifact(this, artifactID, obj_id, artifactTypeID, artifactTypeName, artifactDisplayName);

        } catch (SQLException ex) {
            throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
        } finally {
            dbWriteUnlock();
        }
    }

    /**
     * Add a new blackboard artifact with the given type.
	 * 
     * @param artifactType the type the given artifact should have
	 * @param obj_id the content object id associated with this artifact
     * @return a new blackboard artifact
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    BlackboardArtifact newBlackboardArtifact(ARTIFACT_TYPE artifactType, long obj_id) throws TskCoreException {
        dbWriteLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs;
            int type = artifactType.getTypeID();

            long artifactID = -1;
            s.executeUpdate("INSERT INTO blackboard_artifacts (artifact_id, obj_id, artifact_type_id) VALUES (NULL, " + obj_id + ", " + type + ")");
            rs = s.executeQuery("SELECT artifact_id from blackboard_artifacts WHERE obj_id = " + obj_id + " AND + artifact_type_id = " + type);
            while (rs.next()) {
                if (rs.getLong(1) > artifactID) {
                    artifactID = rs.getLong(1);
                }
            }
            rs.close();
            s.close();
            return new BlackboardArtifact(this, artifactID, obj_id, type, artifactType.getLabel(), artifactType.getDisplayName());

        } catch (SQLException ex) {
            throw new TskCoreException("Error getting or creating a blackboard artifact. " + ex.getMessage(), ex);
        } finally {
            dbWriteUnlock();
        }
    }

    /**
     * Add one of the built in artifact types
	 * 
     * @param type type enum
     * @throws TskException
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    private void addBuiltInArtifactType(ARTIFACT_TYPE type) throws TskCoreException {
        addArtifactType(type.getLabel(), type.getDisplayName(), type.getTypeID());
    }

    /**
     * Add one of the built in attribute types
	 * 
     * @param type type enum
     * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    private void addBuiltInAttrType(ATTRIBUTE_TYPE type) throws TskCoreException {
        addAttrType(type.getLabel(), type.getDisplayName(), type.getTypeID());
    }
	
	/**
	 * Returns the list of AbstractFile Children for a given AbstractFileParent
	 * @param parent the content parent to get abstract file children for 
	 * @param type children type to look for, defined in TSK_DB_FILES_TYPE_ENUM
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
	 */
	List<AbstractFile> getAbstractFileChildren(Content parent, TSK_DB_FILES_TYPE_ENUM type) throws TskCoreException {

        SetParentVisitor setParent = new SetParentVisitor();
		List<AbstractFile> children = new ArrayList<AbstractFile>();

		dbReadLock();
		try {
			Statement s = con.createStatement();
			String query = "select tsk_files.* ";
			query += "from tsk_objects join tsk_files ";
			query += "on tsk_objects.obj_id=tsk_files.obj_id ";
			query += "where (tsk_objects.par_obj_id = " + parent.getId() + " ";
			query += "and tsk_files.type = " + type.getFileType() + ")";
			ResultSet rs = s.executeQuery(query);

			while (rs.next()) {
				if(type == TSK_DB_FILES_TYPE_ENUM.FS) {
					FsContent result;
					if (rs.getLong("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getMetaType()) {
						result = rsHelper.directory(rs, null);
					} else {
						result = rsHelper.file(rs, null);
					}
					result.accept(setParent);
					children.add(result);
				} else {
					LayoutFile lf = new LayoutFile(this, rs.getLong("obj_id"), rs.getString("name"), TskData.TSK_DB_FILES_TYPE_ENUM.valueOf(rs.getLong("type")));
					lf.setParent(parent);
					children.add(lf);
				}
			}
			rs.close();
			s.close();	
		} catch (SQLException ex) {
			throw new TskCoreException("Error getting AbstractFile children for Content.", ex);
		} finally {
			dbReadUnlock();
		}
		return children;
	}

    /**
     * Stores a pair of object ID and its type
     */
    private static class ObjectInfo {

        long id;
        TskData.ObjectType type;

        ObjectInfo(long id, ObjectType type) {
            this.id = id;
            this.type = type;
        }
    }

    /**
     * Get info about children of a given Content from the database.
     * TODO: the results of this method are volumes, file systems, and fs files.
     * @param c Parent object to run query against
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
     */
    Collection<ObjectInfo> getChildrenInfo(Content c) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            String query = "select tsk_objects.obj_id, tsk_objects.type ";
            query += "from tsk_objects left join tsk_files ";
            query += "on tsk_objects.obj_id=tsk_files.obj_id ";
            query += "where tsk_objects.par_obj_id = " + c.getId() + " ";
            ResultSet rs = s.executeQuery(query);
            
            Collection<ObjectInfo> infos = new ArrayList<ObjectInfo>();

            while (rs.next()) {
                infos.add(new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type"))));
            }
            rs.close();
            s.close();
            return infos;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting Children Info for Content.", ex);
        } finally {
            dbReadUnlock();
        }
    }

	
	/**
	 * Get parent info for the parent of the content object
	 * @param c content object to get parent info for
	 * @return the parent object info with the parent object type and id
	 * @throws TskCoreException exception thrown if a critical error occurs within tsk core
	 */
    ObjectInfo getParentInfo(Content c) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("SELECT parent.obj_id, parent.type "
                    + "FROM tsk_objects AS parent JOIN tsk_objects AS child "
                    + "ON child.par_obj_id = parent.obj_id "
                    + "WHERE child.obj_id = " + c.getId());

            ObjectInfo info;

            if (rs.next()) {
                info = new ObjectInfo(rs.getLong("obj_id"), ObjectType.valueOf(rs.getLong("type")));
                rs.close();
                s.close();
                return info;
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("Given content (id: " + c.getId() + ") has no parent.");
            }
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting Parent Info for Content.", ex);
        } finally {
            dbReadUnlock();
        }
    }

	
	/**
	 * Gets parent directory for FsContent object
	 * 
	 * @param fsc FsContent to get parent dir for
	 * @return the parent Directory
	 * @throws TskCoreException thrown if critical error occurred within tsk core
	 */
    Directory getParentDirectory(FsContent fsc) throws TskCoreException {
        if (fsc.isRoot()) {
            throw new TskCoreException("Given FsContent (id: " + fsc.getId() + ") is a root object (can't have parent directory).");
        } else {
            ObjectInfo parentInfo = getParentInfo(fsc);

            Directory parent;

            if (parentInfo.type == ObjectType.ABSTRACTFILE) {
                parent = getDirectoryById(parentInfo.id, fsc.getFileSystem());
            } else {
                throw new TskCoreException("Parent of FsContent (id: " + fsc.getId() + ") has wrong type to be directory: " + parentInfo.type);
            }

            return parent;
        }
    }

	/**
	 * Get content object by content id
	 * @param id to get content object for
	 * @return instance of a Content object (one of its subclasses)
	 * @throws TskCoreException thrown if critical error occurred within tsk core
	 */
    public Content getContentById(long id) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet contentRs = s.executeQuery("select * from tsk_objects where obj_id = " + id);
            ResultSet volumeSystemRs;
            VolumeSystem vs;
            Image img;
            Content ret;
            TskData.ObjectType type = TskData.ObjectType.valueOf(contentRs.getLong("type"));
            switch (type) {
                case IMG:
                    ret = getImageById(id);
                    break;
                case VS:
                    img = getImageById(contentRs.getInt("par_obj_id"));
                    ret = getVolumeSystemById(id, img);
                    break;
                case VOL:
                    volumeSystemRs = s.executeQuery("select * from tsk_objects where obj_id = " + contentRs.getInt("par_obj_id"));
                    img = getImageById(volumeSystemRs.getInt("par_obj_id"));
                    vs = getVolumeSystemById(contentRs.getInt("par_obj_id"), img);
                    volumeSystemRs.close();
                    ret = getVolumeById(id, vs);
                    break;
                case FS:
                    if (contentRs.getInt("par_obj_id") == 0) {
                        img = getImageById(contentRs.getInt("par_obj_id"));
                        ret = getFileSystemById(id, img);
                    } else {
                        ResultSet volumeRs = s.executeQuery("select * from tsk_objects where obj_id = " + contentRs.getInt("par_obj_id"));
                        volumeSystemRs = s.executeQuery(("select * from tsk_objects where obj_id = " + volumeRs.getInt("par_obj_id")));
                        ResultSet imageRs = s.executeQuery(("select * from tsk_objects where obj_id = " + volumeSystemRs.getInt("par_obj_id")));
                        img = getImageById(imageRs.getInt("obj_id"));
                        vs = getVolumeSystemById(volumeSystemRs.getInt("obj_id"), img);
                        Volume v = getVolumeById(volumeRs.getInt("obj_id"), vs);
                        volumeRs.close();
                        volumeSystemRs.close();
                        imageRs.close();
                        ret = getFileSystemById(id, v);
                    }
                    break;
                case ABSTRACTFILE:
                    ret = getAbstractFileById(id);
                    break;
                default:
                    ret = null;
                    break;
            }
            contentRs.close();
            s.close();
            return ret;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting Content by ID.", ex);
        } finally {
            dbReadUnlock();
        }
    }

	/**
	 * Get abstract file object from tsk_files table by its id
	 * @param id id of the file object in tsk_files table
	 * @return AbstractFile object populated
	 * @throws TskCoreException thrown if critical error occurred within tsk core
	 */
    public AbstractFile getAbstractFileById(long id) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();

            ResultSet rs = s.executeQuery("select * from tsk_files where obj_id = " + id);
            List<AbstractFile> results;
            if ((results = resultSetToAbstractFiles(rs)).size() > 0) {
                s.close();
                return results.get(0);
            } else {
                s.close();
            }
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting FsContent by ID.", ex);
        } finally {
            dbReadUnlock();
        }
        throw new TskCoreException("No file found for id " + id);
    }
    
	
	/**
	 * Get file layout ranges from tsk_file_layout, for a file with specified id
	 * @param id of the file to get file layout ranges for
	 * @return list of populated file ranges
	 * @throws TskCoreException thrown if a critical error occurred within tsk core
	 */
    public List<TskFileRange> getFileRanges(long id) throws TskCoreException{
        List<TskFileRange> ranges = new ArrayList<TskFileRange>();
        dbReadLock();
        try {
            Statement s1 = con.createStatement();

            ResultSet rs1 = s1.executeQuery("select * from tsk_file_layout where obj_id = " + id + " order by sequence");

            while(rs1.next()) {
                ranges.add(rsHelper.tskFileRange(rs1));
            }
            rs1.close();
            s1.close();
            return ranges;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting TskFileLayoutRanges by ID.", ex);
        } finally {
            dbReadUnlock();
        }
    }

	
	/**
	 * Get am image by the image object id
	 * @param id of the image object
	 * @return Image object populated
	 * @throws TskCoreException thrown if a critical error occurred within tsk core
	 */
    public Image getImageById(long id) throws TskCoreException {
        dbReadLock();
        try {
            Statement s1 = con.createStatement();

            ResultSet rs1 = s1.executeQuery("select * from tsk_image_info where obj_id = " + id);

            Image temp;
            if (rs1.next()) {
                long obj_id = rs1.getLong("obj_id");
                Statement s2 = con.createStatement();
                ResultSet rs2 = s2.executeQuery("select * from tsk_image_names where obj_id = " + obj_id);
                List<String> imagePaths = new ArrayList<String>();
                while (rs2.next()) {
                    imagePaths.add(rsHelper.imagePath(rs2));
                }

                String path1 = imagePaths.get(0);
                String name = (new java.io.File(path1)).getName();

                temp = rsHelper.image(rs1, name, imagePaths.toArray(new String[imagePaths.size()]));
                rs2.close();
                s2.close();
            } else {
                rs1.close();
                s1.close();
                throw new TskCoreException("No image found for id: " + id);
            }
            rs1.close();
            s1.close();
            return temp;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting Image by ID.", ex);
        } finally {
            dbReadUnlock();
        }
    }

	
	/**
	 * Get a volume system by the volume system object id
	 * @param id id of the volume system
	 * @param parent image containing the volume system
	 * @return populated VolumeSystem object
	 * @throws TskCoreException thrown if a critical error occurred within tsk core
	 */
    VolumeSystem getVolumeSystemById(long id, Image parent) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();

            ResultSet rs = s.executeQuery("select * from tsk_vs_info "
                    + "where obj_id = " + id);
            VolumeSystem temp;

            if (rs.next()) {
                temp = rsHelper.volumeSystem(rs, parent);
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("No volume system found for id:" + id);
            }
            rs.close();
            s.close();
            return temp;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting Volume System by ID.", ex);
        } finally {
            dbReadUnlock();
        }
    }

	
	/**
	 * Get a file system by the object id
	 * @param id of the filesystem 
	 * @param parent parent Image of the file system
	 * @return populated FileSystem object
	 * @throws TskCoreException thrown if a critical error occurred within tsk core
	 */
    FileSystem getFileSystemById(long id, Image parent) throws TskCoreException {
        return getFileSystemByIdHelper(id, parent);
    }
	
	
	/**
	 * Get a file system by the object id
	 * @param id of the filesystem 
	 * @param parent parent Volume of the file system
	 * @return populated FileSystem object
	 * @throws TskCoreException thrown if a critical error occurred within tsk core
	 */
	FileSystem getFileSystemById(long id, Volume parent) throws TskCoreException {
		return getFileSystemByIdHelper(id, parent);
	}
	
	
	/**
	 * Get file system by id and Content parent
	 * @param id of the filesystem to get
	 * @param parent a direct parent Content object
	 * @return populated FileSystem object
	 * @throws TskCoreException thrown if a critical error occurred within tsk core
	 */
	private FileSystem getFileSystemByIdHelper(long id, Content parent) throws TskCoreException {
		dbReadLock();
        try {
            Statement s = con.createStatement();
            FileSystem temp;

            ResultSet rs = s.executeQuery("select * from tsk_fs_info "
                    + "where obj_id = " + id);

            if (rs.next()) {
                temp = rsHelper.fileSystem(rs, parent);
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("No file system found for id:" + id);
            }
            rs.close();
            s.close();

            return temp;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting File System by ID.", ex);
        } finally {
            dbReadUnlock();
        }
	}

	
	/**
	 * Get volume by id
	 * @param id
	 * @param parent volume system
	 * @return populated Volume object
	 * @throws TskCoreException thrown if a critical error occurred within tsk core
	 */
    Volume getVolumeById(long id, VolumeSystem parent) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            Volume temp;

            ResultSet rs = s.executeQuery("select * from tsk_vs_parts "
                    + "where obj_id = " + id);

            if (rs.next()) {
                temp = rsHelper.volume(rs, parent);
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("No volume found for id:" + id);
            }
            rs.close();
            s.close();
            return temp;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting Volume by ID.", ex);
        } finally {
            dbReadUnlock();
        }
    }

	
	/**
	 * Get a directory by id
	 * @param id of the directory object
	 * @param parentFs parent file system
	 * @return populated Directory object
	 * @throws TskCoreException thrown if a critical error occurred within tsk core
	 */
    Directory getDirectoryById(long id, FileSystem parentFs) throws TskCoreException {
        dbReadLock();
        try {
            Statement s = con.createStatement();
            Directory temp;

            ResultSet rs = s.executeQuery("select * from tsk_files "
                    + "where obj_id = " + id);

            if (rs.next() && rs.getLong("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getMetaType()) {
                temp = rsHelper.directory(rs, parentFs);
            } else {
                rs.close();
                s.close();
                throw new TskCoreException("No Directory found for id:" + id);
            }
            rs.close();
            s.close();
            return temp;
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting Directory by ID.", ex);
        } finally {
            dbReadUnlock();
        }
    }

    /**
     * Initializes the entire heritage of the visited Content.
     */
    private class SetParentVisitor implements ContentVisitor<Void> {

        SetParentVisitor() {
        }
        // make File/Directory visits (majority of cases) faster by caching
        // fully initialized parent FileSystems
        Map<Long, FileSystem> fileSystemCache = new HashMap<Long, FileSystem>();

        private void visitFsContent(FsContent fc) {
            try {
                long fileSystemId = fc.fs_obj_id;
                FileSystem parent = fileSystemCache.get(fileSystemId);
                if (parent == null) {
                    parent = getFileSystemByIdHelper(fileSystemId, null);
                    parent.accept(this);
                    fileSystemCache.put(fileSystemId, parent);
                }
                fc.setFileSystem(parent);
            } catch (TskCoreException ex) {
                throw new RuntimeException(ex);
            }
        }

        @Override
        public Void visit(Directory d) {
            visitFsContent(d);
            return null;
        }
        
        @Override
        public Void visit(LayoutFile lf) {
            try {
                ObjectInfo parentInfo = getParentInfo(lf);
				Content parent;
				if (parentInfo.type == ObjectType.IMG) {
					parent = getImageById(parentInfo.id);
				} else if (parentInfo.type == ObjectType.VOL) {
					parent = getVolumeById(parentInfo.id, null);
				} else if (parentInfo.type == ObjectType.FS) {
					parent = getFileSystemByIdHelper(parentInfo.id, null);
				} else {
					throw new IllegalStateException("Parent has wrong type to be FileSystemParent: " + parentInfo.type);
				}
				lf.setParent(parent);
                parent.accept(this);
            } catch (TskCoreException ex) {
                throw new RuntimeException(ex);
            }
            return null;
        }

        @Override
        public Void visit(File f) {
            visitFsContent(f);
            return null;
        }

        @Override
        public Void visit(FileSystem fs) {
            try {
                ObjectInfo parentInfo = getParentInfo(fs);
                Content parent;
                if (parentInfo.type == ObjectType.IMG) {
                    parent = getImageById(parentInfo.id);
                } else if (parentInfo.type == ObjectType.VOL) {
                    parent = getVolumeById(parentInfo.id, null);
                } else {
                    throw new IllegalStateException("Parent has wrong type to be FileSystemParent: " + parentInfo.type);
                }
                fs.setParent(parent);
                parent.accept(this);
            } catch (TskCoreException ex) {
                throw new RuntimeException(ex);
            }
            return null;
        }

        @Override
        public Void visit(Image i) {
            // images are currently parentless
            return null;
        }

        @Override
        public Void visit(Volume v) {
            try {
                ObjectInfo parentInfo = getParentInfo(v);
                VolumeSystem parent;
                if (parentInfo.type == ObjectType.VS) {
                    parent = getVolumeSystemById(parentInfo.id, null);
                } else {
                    throw new IllegalStateException("Parent has wrong type to be VolumeSystem: " + parentInfo.type);
                }
                v.setParent(parent);
                parent.accept(this);
            } catch (TskCoreException ex) {
                throw new RuntimeException(ex);
            }
            return null;
        }

        @Override
        public Void visit(VolumeSystem vs) {
            try {
                ObjectInfo parentInfo = getParentInfo(vs);
                Image parent;
                if (parentInfo.type == ObjectType.IMG) {
                    parent = getImageById(parentInfo.id);
                } else {
                    throw new IllegalStateException("Parent has wrong type to be Image: " + parentInfo.type);
                }
                vs.setParent(parent);
                parent.accept(this);
            } catch (TskCoreException ex) {
                throw new RuntimeException(ex);
            }
            return null;
        }
    }

    /**
     * Helper to return FileSystems in an Image
	 * 
     * @param image Image to lookup FileSystem for
     * @return Collection of FileSystems in the image
     */
    public Collection<FileSystem> getFileSystems(Image image) {
        return new GetFileSystemsVisitor().visit(image);
    }

    /**
     * top-down FileSystem visitor, traverses Content (any parent of FileSystem)
     * and returns all FileSystem children of that parent
     */
    private static class GetFileSystemsVisitor implements
            ContentVisitor<Collection<FileSystem>> {

        @Override
        public Collection<FileSystem> visit(Directory directory) {
            //should never get here
            return Collections.<FileSystem>emptyList();
        }

        @Override
        public Collection<FileSystem> visit(File file) {
            //should never get here
            return Collections.<FileSystem>emptyList();
        }
        
        @Override
        public Collection<FileSystem> visit(LayoutFile lf) {
            return Collections.<FileSystem>emptyList();
        }

        @Override
        public Collection<FileSystem> visit(FileSystem fs) {
            Collection<FileSystem> col = new ArrayList<FileSystem>();
            col.add(fs);
            return col;
        }

        @Override
        public Collection<FileSystem> visit(Image image) {
            return getAllFromChildren(image);
        }

        @Override
        public Collection<FileSystem> visit(Volume volume) {
            return getAllFromChildren(volume);
        }

        @Override
        public Collection<FileSystem> visit(VolumeSystem vs) {
            return getAllFromChildren(vs);
        }

        private Collection<FileSystem> getAllFromChildren(Content parent) {
            Collection<FileSystem> all = new ArrayList<FileSystem>();

            try {
                for (Content child : parent.getChildren()) {
                    all.addAll(child.accept(this));
                }
            } catch (TskCoreException ex) {
            }

            return all;
        }
    }

	/**
	 * Returns the list of direct children for a given Image
	 * 
	 * @param img image to get children for
	 * @return list of Contents (direct image children)
	 * @throws TskCoreException thrown if a critical error occurred within tsk core 
	 */
    List<Content> getImageChildren(Image img) throws TskCoreException {
        Collection<ObjectInfo> childInfos = getChildrenInfo(img);

        List<Content> children = new ArrayList<Content>();

        for (ObjectInfo info : childInfos) {

            if (info.type == ObjectType.VS) {
                children.add(getVolumeSystemById(info.id, img));
            } else if (info.type == ObjectType.FS) {
                children.add(getFileSystemById(info.id, img));
            } else if (info.type == ObjectType.ABSTRACTFILE) {
				children.add(getAbstractFileById(info.id));
            } else {
                throw new TskCoreException("Image has child of invalid type: " + info.type);
            }
        }

        return children;
    }

    /**
     * Returns the list of direct children for a given VolumeSystem
	 * 
	 * @param vs volume system to get children for
	 * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    List<Content> getVolumeSystemChildren(VolumeSystem vs) throws TskCoreException {
        Collection<ObjectInfo> childInfos = getChildrenInfo(vs);

        List<Content> children = new ArrayList<Content>();

        for (ObjectInfo info : childInfos) {

            if (info.type == ObjectType.VOL) {
                children.add(getVolumeById(info.id, vs));
            } else if (info.type == ObjectType.ABSTRACTFILE) {
				children.add(getAbstractFileById(info.id));
            } else {
                throw new TskCoreException("VolumeSystem has child of invalid type: " + info.type);
            }
        }

        return children;
    }

    /**
     * Returns a list of direct children for a given Volume
	 * @param vol volume to get children of
	 * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    List<Content> getVolumeChildren(Volume vol) throws TskCoreException {
        Collection<ObjectInfo> childInfos = getChildrenInfo(vol);

        List<Content> children = new ArrayList<Content>();

        for (ObjectInfo info : childInfos) {
            if (info.type == ObjectType.FS) {
                children.add(getFileSystemById(info.id, vol));
            } else if (info.type == ObjectType.ABSTRACTFILE) {
				children.add(getAbstractFileById(info.id));
            } else {
                throw new TskCoreException("Volume has child of invalid type: " + info.type);
            }
        }

        return children;
    }

    /**
     * Returns a list of direct children for a given file system
	 * @param fs file system to get the list of children for
	 * @return the list of direct files children of the filesystem 
	 * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    List<AbstractFile> getFileSystemChildren(FileSystem fs) throws TskCoreException {
        List<AbstractFile> ret = new ArrayList<AbstractFile>();
		for(TskData.TSK_DB_FILES_TYPE_ENUM type : TskData.TSK_DB_FILES_TYPE_ENUM.values()) {
			ret.addAll(this.getAbstractFileChildren(fs, type));
		}
		return ret;
    }

    /**
     * Returns a list of direct children for a given directory
	 * @param dir directory to get the list of direct children for
	 * @return list of direct children (files) for a given directory
	 * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    List<AbstractFile> getDirectoryChildren(Directory dir) throws TskCoreException {
        List<AbstractFile> ret = new ArrayList<AbstractFile>();
		for(TskData.TSK_DB_FILES_TYPE_ENUM type : TskData.TSK_DB_FILES_TYPE_ENUM.values()) {
			ret.addAll(this.getAbstractFileChildren(dir, type));
		}
		return ret;
    }

    /**
     * Returns a map of image object IDs to a list of fully qualified file paths for that image
	 * 
	 * @return map of image object IDs to file paths
	 * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    public Map<Long, List<String>> getImagePaths() throws TskCoreException {
        Map<Long, List<String>> imgPaths = new LinkedHashMap<Long, List<String>>();

        dbReadLock();
        try {
            Statement s1 = con.createStatement();

            ResultSet rs1 = s1.executeQuery("select * from tsk_image_info");

            while (rs1.next()) {
                long obj_id = rs1.getLong("obj_id");
                Statement s2 = con.createStatement();
                ResultSet rs2 = s2.executeQuery("select * from tsk_image_names where obj_id = " + obj_id);
                List<String> paths = new ArrayList<String>();
                while (rs2.next()) {
                    paths.add(rsHelper.imagePath(rs2));
                }
                rs2.close();
                s2.close();
                imgPaths.put(obj_id, paths);
            }

            rs1.close();
            s1.close();
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting image paths.", ex);
        } finally {
            dbReadUnlock();
        }


        return imgPaths;
    }

    /**
     * Set the file paths for the image given by obj_id
	 * 
     * @param obj_id the ID of the image to update
     * @param paths the fully qualified path to the files that make up the image
     * @throws TskCoreException exception thrown when critical error occurs within tsk core and the update fails
     */
    public void setImagePaths(long obj_id, List<String> paths) throws TskCoreException {

        dbWriteLock();
        try {
            Statement s1 = con.createStatement();

            s1.executeUpdate("delete from tsk_image_names where obj_id = " + obj_id);
            for (int i = 0; i < paths.size(); i++) {
                s1.executeUpdate("insert into tsk_image_names values (" + obj_id + ", \"" + paths.get(i) + "\", " + i + ")");
            }

            s1.close();
        } catch (SQLException ex) {
            throw new TskCoreException("Error updating image paths.", ex);
        } finally {
            dbWriteUnlock();
        }

    }
	
	/**
     * Creates file object from a SQL query result set of rows from the tsk_files
     * table.  Assumes that the query was of the form
     * "SELECT * FROM tsk_files WHERE XYZ".
	 * 
     * @param rs ResultSet to get content from. Caller is responsible for closing it.
     * @return list of file objects from tsk_files table containing the results
     * @throws SQLException if the query fails
     */
    public List<AbstractFile> resultSetToAbstractFiles(ResultSet rs) throws SQLException { 
        SetParentVisitor setParent = new SetParentVisitor();
        ArrayList<AbstractFile> results = new ArrayList<AbstractFile>();

        dbReadLock();
		try {
			while (rs.next()) {
				if (rs.getLong("type") == TSK_DB_FILES_TYPE_ENUM.FS.getFileType() ) {
					FsContent result;
					if (rs.getLong("meta_type") == TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getMetaType()) {
						result = rsHelper.directory(rs, null);
					} else {
						result = rsHelper.file(rs, null);
					}
					result.accept(setParent);
					results.add(result);
				} else {
					LayoutFile lf = new LayoutFile(this, rs.getLong("obj_id"), rs.getString("name"), TskData.TSK_DB_FILES_TYPE_ENUM.valueOf(rs.getLong("type")));
					lf.accept(setParent);
					results.add(lf);
				}
			}
		} finally {
            dbReadUnlock();
        }

        return results;
    }
	
	/**
	 * Creates FsContent objects from SQL query result set on tsk_files table
	 * 
	 * @param rs the result set with the query results
	 * @return list of fscontent objects matching the query
	 * @throws SQLException if SQL query result getting failed
	 */
	public List<FsContent> resultSetToFsContents(ResultSet rs) throws SQLException {
		List<FsContent> results = new ArrayList<FsContent>();
		List<AbstractFile> temp = resultSetToAbstractFiles(rs);
		for(AbstractFile f : temp) {
			if(f.getType().equals(TskData.TSK_DB_FILES_TYPE_ENUM.FS)) {
				results.add((FsContent)f);
			}
		}
		return results;
	}

    /**
     * Process a read-only query on the tsk database, any table
	 * Can be used to e.g. to find files of a given criteria.
     * resultSetToFsContents() will convert the results to useful objects.
     * MUST CALL closeRunQuery() when done
     *
     * @param query  the given string query to run
	 * @return	   the resultSet from running the query.
     * Caller MUST CALL closeRunQuery(resultSet) as soon as possible, when done with retrieving data from the resultSet
     * @throws SQLException if error occurred during the query
     */
    public ResultSet runQuery(String query) throws SQLException {
        Statement statement;
        dbReadLock();
        try {
            statement = con.createStatement();
            ResultSet rs = statement.executeQuery(query);
            return rs;
        } finally {
            //TODO unlock should be done in closeRunQuery()
            //but currently not all code calls closeRunQuery - need to fix this
            dbReadUnlock();
        }
    }

    /**
     * Closes ResultSet and its Statement previously retrieved from runQuery()
     *
     * @param resultSet with its Statement to close
     * @throws SQLException of closing the query results failed
     */
    public void closeRunQuery(ResultSet resultSet) throws SQLException {
        final Statement statement = resultSet.getStatement();
        resultSet.close();
        if (statement != null) {
            statement.close();
        }
    }


    @Override
    public void finalize() {
        close();
    }

    /**
     * Closes the database connection of this instance.
     */
    private void closeConnection() {
        SleuthkitCase.dbWriteLock();
        try {
            if (con != null) {
                con.close();
                con = null;
            }

        } catch (SQLException e) {
            // connection close failed.
            Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING,
                    "Error closing connection.", e);
        } finally {
            SleuthkitCase.dbWriteUnlock();
        }
    }

    /**
     * Call to free resources when done with instance.
     */
    public void close() {
        System.err.println(this.hashCode() + " closed");
        System.err.flush();
        SleuthkitCase.dbWriteLock();
        this.closeConnection();
        try {
            if (this.caseHandle != null) {
                this.caseHandle.free();
                this.caseHandle = null;
            }
        } catch (TskCoreException ex) {
            Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING,
                    "Error freeing case handle.", ex);
        } finally {
            SleuthkitCase.dbWriteUnlock();
        }
    }

    /**
     * Make a duplicate / backup copy of the current case database
     * Makes a new copy only, and continues to use the current db
     * 
     * @param newDBPath path to the copy to be created.  File will be overwritten if it exists
     * @throws IOException if copying fails
     */
    public void copyCaseDB(String newDBPath) throws IOException {
        InputStream in = null;
        OutputStream out = null;
        SleuthkitCase.dbReadLock();
        try {
            InputStream inFile = new FileInputStream(this.dbPath);
            in = new BufferedInputStream(inFile);
            OutputStream outFile = new FileOutputStream(newDBPath);
            out = new BufferedOutputStream(outFile);
            int readBytes = 0;
            while ((readBytes = in.read()) != -1) {
                out.write(readBytes);
            }
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
                if (out != null) {
                    out.flush();
                    out.close();
                }
            } catch (IOException e) {
                Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING, "Could not close streams after db copy", e);
            }
            SleuthkitCase.dbReadUnlock();
        }
    }

    /**
     * Store the known status for the FsContent in the database
     * Note: will not update status if content is already 'Known Bad'
     *
	 * @param	fsContent	The FsContent object
	 * @param	fileKnown	The object's known status
	 * @return				true if the known status was updated, false otherwise
	 * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    public boolean setKnown(FsContent fsContent, FileKnown fileKnown) throws TskCoreException {
        long id = fsContent.getId();
        FileKnown currentKnown = fsContent.getKnown();
        if (currentKnown.compareTo(fileKnown) > 0) {
            return false;
        }
        SleuthkitCase.dbWriteLock();
        try {
            Statement s = con.createStatement();
            s.executeUpdate("UPDATE tsk_files "
                    + "SET known='" + fileKnown.toLong() + "' "
                    + "WHERE obj_id=" + id);
            s.close();
        } catch (SQLException ex) {
            throw new TskCoreException("Error setting Known status.", ex);
        } finally {
            SleuthkitCase.dbWriteUnlock();
        }
        return true;
    }

    /**
     * Store the md5Hash for the FsContent in the database
     *
	 * @param	fsContent	The FsContent object
	 * @param	md5Hash		The object's md5Hash
	 * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    void setMd5Hash(FsContent fsContent, String md5Hash) throws TskCoreException {
        long id = fsContent.getId();
        SleuthkitCase.dbWriteLock();
        try {
            Statement s = con.createStatement();
            s.executeUpdate("UPDATE tsk_files "
                    + "SET md5='" + md5Hash + "' "
                    + "WHERE obj_id=" + id);
            s.close();
        } catch (SQLException ex) {
            throw new TskCoreException("Error setting MD5 hash.", ex);
        } finally {
            SleuthkitCase.dbWriteUnlock();
        }
    }

    /**
     * Look up the given hash in the NSRL database
     * @param md5Hash The hash to look up
     * @return the status of the hash in the NSRL
     * @throws TskCoreException thrown if a critical error occurred within tsk core  
     */
    public TskData.FileKnown nsrlLookupMd5(String md5Hash) throws TskCoreException {
        return SleuthkitJNI.nsrlHashLookup(md5Hash);
    }

    /**
     * Look up the given hash in the known bad database
     * @param md5Hash The hash to look up
     * @param dbHandle The handle of the open database to look in
     * @return the status of the hash in the known bad database
     * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    public TskData.FileKnown knownBadLookupMd5(String md5Hash, int dbHandle) throws TskCoreException {
        return SleuthkitJNI.knownBadHashLookup(md5Hash, dbHandle);
    }

	
    /**
     * Return the number of objects in the database of a given file type.
     *
     * @param contentType Type of file to count
     * @return Number of objects with that type.
     * @throws TskCoreException thrown if a critical error occurred within tsk core 
     */
    public int countFsContentType(TskData.TSK_FS_META_TYPE_ENUM contentType) throws TskCoreException {
        int count = 0;
        Long contentLong = contentType.getMetaType();
        dbReadLock();
        try {
            Statement s = con.createStatement();
            ResultSet rs = s.executeQuery("select count(*) from tsk_files where meta_type = '" + contentLong.toString() + "'");
            while (rs.next()) {
                count = rs.getInt("count(*)");
            }
            rs.close();
            s.close();
        } catch (SQLException ex) {
            throw new TskCoreException("Error getting number of objects.", ex);
        } finally {
            dbReadUnlock();
        }
        return count;
    }

    /**
     * Escape the single quotes in the given string so they can be added to the SQL db
	 * 
     * @param text
     * @return text the escaped version
     */
    private static String escapeForBlackboard(String text) {
        if (text != null)
            text = text.replaceAll("'", "''");
        return text;
    }
	
	/**
	 * Find all the files with the given MD5 hash.
	 * @param md5Hash	hash value to match files with
	 * @return List of FsContent with the given hash
	 */
	public List<FsContent> findFilesByMd5(String md5Hash) {
		ResultSet rs = null;
		Statement s = null;
        dbReadLock();
        try {
			s = con.createStatement();
            rs = s.executeQuery("SELECT * FROM tsk_files "
                    + "WHERE type = '" + TskData.TSK_DB_FILES_TYPE_ENUM.FS.getFileType() + "' "
					+ "AND dir_type = '" + TskData.TSK_FS_NAME_TYPE_ENUM.REG.getDirType() + "' "
                    + "AND md5 = '" + md5Hash + "' "
					+ "AND size > '0'");
            return resultSetToFsContents(rs);
        } catch (SQLException ex) {
            Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING, "Error querying database.", ex);
        } finally {
            if(rs != null) {
                try {
                    rs.close();
					s.close();
                } catch (SQLException ex) {
                    Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING, "Unable to close ResultSet and Statement.", ex);
                }
            }
            dbReadUnlock();
        }
        return new ArrayList<FsContent>();
	}
	
	/**
	 * Query all the files to verify if they have an MD5 hash associated with them.
	 * @return true if all files have an MD5 hash
	 */
	public boolean allFilesMd5Hashed() {
		ResultSet rs = null;
		Statement s = null;
        dbReadLock();
        try {
			s = con.createStatement();
            rs = s.executeQuery("SELECT COUNT(*) FROM tsk_files "
                    + "WHERE type = '" + TskData.TSK_DB_FILES_TYPE_ENUM.FS.getFileType() + "' "
                    + "AND dir_type = '" + TskData.TSK_FS_NAME_TYPE_ENUM.REG.getDirType() + "' "
                    + "AND md5 IS NULL "
					+ "AND size > '0'");
            rs.next();
            int size = rs.getInt(1);
            if(size==0) {
                return true;
            }
        } catch (SQLException ex) {
            Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING, "Failed to query for all the files.", ex);
        } finally {
            if(rs != null) {
                try {
                    rs.close();
					s.close();
                } catch (SQLException ex) {
                    Logger.getLogger(SleuthkitCase.class.getName()).log(Level.WARNING, "Failed to close the result set.", ex);
                }
            }
            dbReadUnlock();
        }
		return false;
	}

}
