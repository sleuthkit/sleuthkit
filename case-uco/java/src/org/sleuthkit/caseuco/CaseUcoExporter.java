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

import com.google.gson.Gson;
import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_DEVICE_ATTACHED;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_EMAIL_MSG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_EXTRACTED_TEXT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GEN_INFO;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_HASHSET_HIT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_INSTALLED_PROG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_MESSAGE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_METADATA_EXIF;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_OS_ACCOUNT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_OS_INFO;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_RECENT_OBJECT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_SERVICE_ACCOUNT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_BOOKMARK;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_SEARCH_QUERY;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_ACCOUNT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_BLUETOOTH_ADAPTER;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_BLUETOOTH_PAIRING;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CALENDAR_ENTRY;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_DATA_SOURCE_USAGE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_DEVICE_INFO;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_ENCRYPTION_DETECTED;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_ENCRYPTION_SUSPECTED;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_BOOKMARK;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_LAST_KNOWN_LOCATION;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_ROUTE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_SEARCH;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_ARTIFACT_HIT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_OBJECT_DETECTED;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_PROG_RUN;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_REMOTE_DRIVE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_SIM_ATTACHED;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_SPEED_DIAL_ENTRY;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_VERIFICATION_FAILED;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WIFI_NETWORK;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WIFI_NETWORK_ADAPTER;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_CLIPBOARD_CONTENT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACK;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_METADATA;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_TL_EVENT;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_USER_CONTENT_SUSPECTED;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_CACHE;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_FORM_ADDRESS;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_ASSOCIATED_OBJECT;

import org.sleuthkit.datamodel.ContentTag;
import org.sleuthkit.datamodel.DataSource;
import org.sleuthkit.datamodel.FileSystem;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.Pool;
import org.sleuthkit.datamodel.Volume;
import org.sleuthkit.datamodel.VolumeSystem;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TimelineEventType;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.attributes.BlackboardJsonAttrUtil;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints;
import org.sleuthkit.datamodel.blackboardutils.attributes.MessageAttachments;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskData.DbType;

/**
 * Exports Sleuth Kit DataModel objects to CASE. The CASE JSON output is
 * configured to be serialized with Gson. Each export method will produce a list
 * of CASE JSON objects. Clients should loop through this list and write these
 * objects to any OutputStream via Gson. See the Gson documentation for more
 * information on object serialization.
 *
 * NOTE: The exporter behavior can be configured by passing configuration
 * parameters in a custom Properties instance. A list of available configuration
 * properties can be found in the README.md file.
 */
public class CaseUcoExporter {

    private static final String INCLUDE_PARENT_CHILD_RELATIONSHIPS_PROP = "exporter.relationships.includeParentChild";
    private static final String DEFAULT_PARENT_CHILD_RELATIONSHIPS_VALUE = "true";

    private final Gson gson;

    private final SleuthkitCase sleuthkitCase;
    private CaseUcoUUIDService uuidService;

    private Properties props;

    /**
     * Creates a default CaseUcoExporter.
     *
     * @param sleuthkitCase The sleuthkit case instance containing the data to
     * be exported.
     */
    public CaseUcoExporter(SleuthkitCase sleuthkitCase) {
        this(sleuthkitCase, new Properties());
    }

    /**
     * Creates a CaseUcoExporter configured to the properties present in the
     * Properties instance.
     *
     * A list of available configuration properties can be found in the
     * README.md file.
     *
     * @param sleuthkitCase The sleuthkit case instance containing the data to
     * be exported.
     * @param props Properties instance containing supported configuration
     * parameters.
     */
    public CaseUcoExporter(SleuthkitCase sleuthkitCase, Properties props) {
        this.sleuthkitCase = sleuthkitCase;
        this.props = props;
        this.setUUIDService(new CaseUcoUUIDServiceImpl(sleuthkitCase));
        this.gson = new Gson();
    }

    /**
     * Overrides the default UUID implementation, which is used to generate the
     * unique @id properties in the CASE output. Some use cases may require a
     * different value for @id, such as a web service (where this value should
     * contain a URL).
     *
     * @param uuidService A custom UUID implementation, which will be used to
     * generate @id values in all export methods.
     *
     * @return reference to this, for chaining configuration method calls.
     */
    public final CaseUcoExporter setUUIDService(CaseUcoUUIDService uuidService) {
        this.uuidService = uuidService;
        return this;
    }

    /**
     * Exports the SleuthkitCase instance passed during initialization to CASE.
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportSleuthkitCase() throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        String caseDirPath = sleuthkitCase
                .getDbDirPath()
                .replaceAll("\\\\", "/");

        Trace export = new Trace(this.uuidService.createUUID(sleuthkitCase));

        if (sleuthkitCase.getDatabaseType().equals(DbType.POSTGRESQL)) {
            export.addBundle(new File()
                    .setFilePath(caseDirPath)
                    .setIsDirectory(true));
        } else {
            export.addBundle(new File()
                    .setFilePath(caseDirPath + "/" + sleuthkitCase.getDatabaseName())
                    .setIsDirectory(false));
        }

        addToOutput(export, output);
        return output;
    }

    /**
     * Exports an AbstractFile instance to CASE.
     *
     * @param file AbstractFile instance to export
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportAbstractFile(AbstractFile file) throws TskCoreException {
        return exportAbstractFile(file, null);
    }

    /**
     * Exports an AbstractFile instance to CASE.
     *
     * @param file AbstractFile instance to export
     * @param localPath The location of the file on secondary storage, somewhere
     * other than the case. Example: local disk. This value will be ignored if
     * null
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportAbstractFile(AbstractFile file, String localPath) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        ContentData contentData = new ContentData()
                .setMimeType(file.getMIMEType())
                .setSizeInBytes(file.getSize())
                .setMd5Hash(file.getMd5Hash());

        if (localPath != null) {
            Trace localPathTrace = new BlankTraceNode()
                    .addBundle(new URL()
                            .setFullValue(localPath));
            contentData.setDataPayloadReferenceUrl(localPathTrace);

            addToOutput(localPathTrace, output);
        }

        File fileExport = new File()
                .setAccessedTime(file.getAtime())
                .setExtension(file.getNameExtension())
                .setFileName(file.getName())
                .setFilePath(file.getUniquePath())
                .setIsDirectory(file.isDir())
                .setSizeInBytes(file.getSize());
        fileExport.setModifiedTime(file.getMtime());
        fileExport.setCreatedTime(file.getCrtime());

        Trace export = new Trace(this.uuidService.createUUID(file))
                .addBundle(contentData)
                .addBundle(fileExport);

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(file.getDataSource()));

        return output;
    }

    /**
     * Exports a ContentTag instance to CASE.
     *
     * @param contentTag ContentTag instance to export
     * @return A collection of CASE JSON elements
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportContentTag(ContentTag contentTag) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Annotation annotation = new Annotation(this.uuidService.createUUID(contentTag))
                .addObject(this.uuidService.createUUID(contentTag.getContent()));
        annotation.setDescription(contentTag.getComment());
        annotation.addTag(contentTag.getName().getDisplayName());

        addToOutput(annotation, output);
        return output;
    }

    /**
     * Exports a DataSource instance to CASE.
     *
     * @param dataSource DataSource instance to export
     * @return A collection of CASE JSON elements
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportDataSource(DataSource dataSource) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(dataSource))
                .addBundle(new File()
                        .setFilePath(getDataSourcePath(dataSource)))
                .addBundle(new ContentData()
                        .setSizeInBytes(dataSource.getSize()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(this.sleuthkitCase));

        return output;
    }

    String getDataSourcePath(DataSource dataSource) {
        String dataSourcePath = "";
        if (dataSource instanceof Image) {
            String[] paths = ((Image) dataSource).getPaths();
            if (paths.length > 0) {
                dataSourcePath = paths[0];
            }
        } else {
            dataSourcePath = dataSource.getName();
        }
        dataSourcePath = dataSourcePath.replaceAll("\\\\", "/");
        return dataSourcePath;
    }

    /**
     * Exports a FileSystem instance to CASE.
     *
     * @param fileSystem FileSystem instance to export
     * @return A collection of CASE JSON elements
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportFileSystem(FileSystem fileSystem) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(fileSystem))
                .addBundle(new org.sleuthkit.caseuco.FileSystem()
                        .setFileSystemType(fileSystem.getFsType())
                        .setCluserSize(fileSystem.getBlock_size()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(fileSystem.getParent()));

        return output;
    }

    /**
     * Exports a Pool instance to CASE.
     *
     * @param pool Pool instance to export
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportPool(Pool pool) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(pool))
                .addBundle(new ContentData()
                        .setSizeInBytes(pool.getSize()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(pool.getParent()));

        return output;
    }

    /**
     * Exports a Volume instance to CASE.
     *
     * @param volume Volume instance to export
     * @return A collection of CASE JSON elements
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportVolume(Volume volume) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(volume));
        org.sleuthkit.caseuco.Volume volumeFacet = new org.sleuthkit.caseuco.Volume();
        if (volume.getLength() > 0) {
            volumeFacet.setSectorSize(volume.getSize() / volume.getLength());
        }
        export.addBundle(volumeFacet)
                .addBundle(new ContentData()
                        .setSizeInBytes(volume.getSize()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(volume.getParent()));

        return output;

    }

    /**
     * Exports a VolumeSystem instance to CASE.
     *
     * @param volumeSystem VolumeSystem instance to export
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportVolumeSystem(VolumeSystem volumeSystem) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(volumeSystem))
                .addBundle(new ContentData()
                        .setSizeInBytes(volumeSystem.getSize()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(volumeSystem.getParent()));

        return output;
    }

    /**
     * Exports a BlackboardArtifact instance to CASE.
     *
     * @param artifact BlackboardArtifact instance to export
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     * @throws ContentNotExportableException if the content could not be
     * exported, even in part, to CASE.
     * @throws BlackboardJsonAttrUtil.InvalidJsonException If a JSON valued
     * attribute could not be correctly deserialized.
     */
    public List<JsonElement> exportBlackboardArtifact(BlackboardArtifact artifact) throws TskCoreException,
            ContentNotExportableException, BlackboardJsonAttrUtil.InvalidJsonException {
        List<JsonElement> output = new ArrayList<>();

        String uuid = this.uuidService.createUUID(artifact);
        int artifactTypeId = artifact.getArtifactTypeID();

        if (TSK_GEN_INFO.getTypeID() == artifactTypeId) {
            assembleGenInfo(uuid, artifact, output);
        } else if (TSK_WEB_BOOKMARK.getTypeID() == artifactTypeId) {
            assembleWebBookmark(uuid, artifact, output);
        } else if (TSK_WEB_COOKIE.getTypeID() == artifactTypeId) {
            assembleWebCookie(uuid, artifact, output);
        } else if (TSK_WEB_HISTORY.getTypeID() == artifactTypeId) {
            assembleWebHistory(uuid, artifact, output);
        } else if (TSK_WEB_DOWNLOAD.getTypeID() == artifactTypeId) {
            assembleWebDownload(uuid, artifact, output);
        } else if (TSK_RECENT_OBJECT.getTypeID() == artifactTypeId) {
            assembleRecentObject(uuid, artifact, output);
        } else if (TSK_INSTALLED_PROG.getTypeID() == artifactTypeId) {
            assembleInstalledProg(uuid, artifact, output);
        } else if (TSK_HASHSET_HIT.getTypeID() == artifactTypeId) {
            assembleHashsetHit(uuid, artifact, output);
        } else if (TSK_DEVICE_ATTACHED.getTypeID() == artifactTypeId) {
            assembleDeviceAttached(uuid, artifact, output);
        } else if (TSK_INTERESTING_FILE_HIT.getTypeID() == artifactTypeId) {
            assembleInterestingFileHit(uuid, artifact, output);
        } else if (TSK_EMAIL_MSG.getTypeID() == artifactTypeId) {
            assembleEmailMessage(uuid, artifact, output);
        } else if (TSK_EXTRACTED_TEXT.getTypeID() == artifactTypeId) {
            assembleExtractedText(uuid, artifact, output);
        } else if (TSK_WEB_SEARCH_QUERY.getTypeID() == artifactTypeId) {
            assembleWebSearchQuery(uuid, artifact, output);
        } else if (TSK_METADATA_EXIF.getTypeID() == artifactTypeId) {
            assembleMetadataExif(uuid, artifact, output);
        } else if (TSK_OS_INFO.getTypeID() == artifactTypeId) {
            assembleOsInfo(uuid, artifact, output);
        } else if (TSK_OS_ACCOUNT.getTypeID() == artifactTypeId) {
            assembleOsAccount(uuid, artifact, output);
        } else if (TSK_SERVICE_ACCOUNT.getTypeID() == artifactTypeId) {
            assembleServiceAccount(uuid, artifact, output);
        } else if (TSK_CONTACT.getTypeID() == artifactTypeId) {
            assembleContact(uuid, artifact, output);
        } else if (TSK_MESSAGE.getTypeID() == artifactTypeId) {
            assembleMessage(uuid, artifact, output);
        } else if (TSK_CALLLOG.getTypeID() == artifactTypeId) {
            assembleCallog(uuid, artifact, output);
        } else if (TSK_CALENDAR_ENTRY.getTypeID() == artifactTypeId) {
            assembleCalendarEntry(uuid, artifact, output);
        } else if (TSK_SPEED_DIAL_ENTRY.getTypeID() == artifactTypeId) {
            assembleSpeedDialEntry(uuid, artifact, output);
        } else if (TSK_BLUETOOTH_PAIRING.getTypeID() == artifactTypeId) {
            assembleBluetoothPairing(uuid, artifact, output);
        } else if (TSK_GPS_BOOKMARK.getTypeID() == artifactTypeId) {
            assembleGpsBookmark(uuid, artifact, output);
        } else if (TSK_GPS_LAST_KNOWN_LOCATION.getTypeID() == artifactTypeId) {
            assembleGpsLastKnownLocation(uuid, artifact, output);
        } else if (TSK_GPS_SEARCH.getTypeID() == artifactTypeId) {
            assembleGpsSearch(uuid, artifact, output);
        } else if (TSK_PROG_RUN.getTypeID() == artifactTypeId) {
            assembleProgRun(uuid, artifact, output);
        } else if (TSK_ENCRYPTION_DETECTED.getTypeID() == artifactTypeId) {
            assembleEncryptionDetected(uuid, artifact, output);
        } else if (TSK_INTERESTING_ARTIFACT_HIT.getTypeID() == artifactTypeId) {
            assembleInterestingArtifact(uuid, artifact, output);
        } else if (TSK_GPS_ROUTE.getTypeID() == artifactTypeId) {
            assembleGPSRoute(uuid, artifact, output);
        } else if (TSK_REMOTE_DRIVE.getTypeID() == artifactTypeId) {
            assembleRemoteDrive(uuid, artifact, output);
        } else if (TSK_ACCOUNT.getTypeID() == artifactTypeId) {
            assembleAccount(uuid, artifact, output);
        } else if (TSK_ENCRYPTION_SUSPECTED.getTypeID() == artifactTypeId) {
            assembleEncryptionSuspected(uuid, artifact, output);
        } else if (TSK_OBJECT_DETECTED.getTypeID() == artifactTypeId) {
            assembleObjectDetected(uuid, artifact, output);
        } else if (TSK_WIFI_NETWORK.getTypeID() == artifactTypeId) {
            assembleWifiNetwork(uuid, artifact, output);
        } else if (TSK_DEVICE_INFO.getTypeID() == artifactTypeId) {
            assembleDeviceInfo(uuid, artifact, output);
        } else if (TSK_SIM_ATTACHED.getTypeID() == artifactTypeId) {
            assembleSimAttached(uuid, artifact, output);
        } else if (TSK_BLUETOOTH_ADAPTER.getTypeID() == artifactTypeId) {
            assembleBluetoothAdapter(uuid, artifact, output);
        } else if (TSK_WIFI_NETWORK_ADAPTER.getTypeID() == artifactTypeId) {
            assembleWifiNetworkAdapter(uuid, artifact, output);
        } else if (TSK_VERIFICATION_FAILED.getTypeID() == artifactTypeId) {
            assembleVerificationFailed(uuid, artifact, output);
        } else if (TSK_DATA_SOURCE_USAGE.getTypeID() == artifactTypeId) {
            assembleDataSourceUsage(uuid, artifact, output);
        } else if (TSK_WEB_FORM_ADDRESS.getTypeID() == artifactTypeId) {
            assembleWebFormAddress(uuid, artifact, output);
        } else if (TSK_WEB_CACHE.getTypeID() == artifactTypeId) {
            assembleWebCache(uuid, artifact, output);
        } else if (TSK_TL_EVENT.getTypeID() == artifactTypeId) {
            assembleTimelineEvent(uuid, artifact, output);
        } else if (TSK_CLIPBOARD_CONTENT.getTypeID() == artifactTypeId) {
            assembleClipboardContent(uuid, artifact, output);
        } else if (TSK_ASSOCIATED_OBJECT.getTypeID() == artifactTypeId) {
            assembleAssociatedObject(uuid, artifact, output);
        } else if (TSK_USER_CONTENT_SUSPECTED.getTypeID() == artifactTypeId) {
            assembleUserContentSuspected(uuid, artifact, output);
        } else if (TSK_METADATA.getTypeID() == artifactTypeId) {
            assembleMetadata(uuid, artifact, output);
        } else if (TSK_GPS_TRACK.getTypeID() == artifactTypeId) {
            assembleGpsTrack(uuid, artifact, output);
        }

        if (output.isEmpty()) {
            throw new ContentNotExportableException(String.format(
                    "Artifact [id:%d, type:%d] is either not supported "
                    + "or did not have any exported attributes.", artifact.getId(), artifactTypeId));
        }

        addParentChildRelationship(output, uuid,
                this.uuidService.createUUID(artifact.getParent()));

        return output;
    }

    private void assembleWebCookie(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new ContentData()
                        .setDataPayload(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VALUE)));

        Trace cookieDomainNode = new BlankTraceNode()
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)));

        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        BrowserCookie cookie = new BrowserCookie()
                .setCookieName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME))
                .setCookieDomain(cookieDomainNode)
                .setApplication(applicationNode)
                .setAccessedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                .setExpirationTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END));
        cookie.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));

        export.addBundle(cookie);

        addToOutput(export, output);
        addToOutput(cookieDomainNode, output);
        addToOutput(applicationNode, output);
    }

    private void assembleWebBookmark(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        BrowserBookmark bookmark = new BrowserBookmark()
                .setUrlTargeted(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL))
                .setApplication(applicationNode);
        bookmark.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        bookmark.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));

        Trace export = new Trace(uuid)
                .addBundle(bookmark)
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)));

        addToOutput(export, output);
        addToOutput(applicationNode, output);
    }

    private void assembleGenInfo(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Hash hash = new Hash(uuid, getValueIfPresent(artifact, StandardAttributeTypes.TSK_HASH_PHOTODNA));
        addToOutput(hash, output);
    }

    private void assembleWebHistory(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace userNameNode = new BlankTraceNode();

        IdentityFacet identityFacet = new IdentityFacet();
        identityFacet.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_NAME));
        userNameNode.addBundle(identityFacet);

        Trace export = new Trace(uuid)
                .addBundle(new URL()
                        .setUserName(userNameNode)
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        addToOutput(export, output);
        addToOutput(userNameNode, output);
    }

    private void assembleWebDownload(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new File()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        addToOutput(export, output);
    }

    private void assembleDeviceAttached(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Device()
                        .setManufacturer(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MAKE))
                        .setModel(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MODEL))
                        .setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_ID)))
                .addBundle(new MACAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        addToOutput(export, output);
    }

    private void assembleHashsetHit(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        addToOutput(export, output);
    }

    private void assembleInstalledProg(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new File()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH_SOURCE)));
        Software software = new Software();
        software.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME));
        export.addBundle(software);

        File file = new File()
                .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH));
        file.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        file.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        export.addBundle(file);

        addToOutput(export, output);
    }

    private void assembleRecentObject(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        WindowsRegistryValue registryValue = new WindowsRegistryValue()
                .setData(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VALUE));
        registryValue.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        export.addBundle(registryValue);

        File file = new File()
                .setAccessedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_ACCESSED));
        file.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        export.addBundle(file);

        addToOutput(export, output);

        Assertion assertion = new BlankAssertionNode()
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        addToOutput(assertion, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(assertion.getId())
                .setTarget(uuid), output);
    }

    private void assembleInterestingFileHit(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        addToOutput(export, output);
    }

    private void assembleExtractedText(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new ExtractedString()
                        .setStringValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT)));
        addToOutput(export, output);
    }

    private void assembleEmailMessage(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace bccNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_BCC)));

        Trace ccNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CC)));

        Trace fromNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_FROM)));

        Trace headerRawNode = new BlankTraceNode()
                .addBundle(new ExtractedString()
                        .setStringValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_HEADERS)));

        EmailMessage emailMessage = new EmailMessage();
        String html = getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CONTENT_HTML);
        String plain = getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CONTENT_PLAIN);
        String rtf = getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CONTENT_RTF);

        if (html != null) {
            emailMessage.setBody(html);
            emailMessage.setContentType("text/html");
        } else if (rtf != null) {
            emailMessage.setBody(rtf);
            emailMessage.setContentType("text/rtf");
        } else if (plain != null) {
            emailMessage.setBody(plain);
            emailMessage.setContentType("text/plain");
        }

        Trace export = new Trace(uuid)
                .addBundle(emailMessage
                        .setReceivedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_RCVD))
                        .setSentTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_SENT))
                        .setBcc(bccNode)
                        .setCc(ccNode)
                        .setFrom(fromNode)
                        .setHeaderRaw(headerRawNode)
                        .setMessageID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MSG_ID))
                        .setSubject(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SUBJECT)))
                .addBundle(new File()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)));

        addToOutput(export, output);
        addToOutput(bccNode, output);
        addToOutput(ccNode, output);
        addToOutput(fromNode, output);
        addToOutput(headerRawNode, output);
    }

    private void assembleWebSearchQuery(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        Trace export = new Trace(uuid)
                .addBundle(new Note()
                        .setText(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT)))
                .addBundle(new Domain()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new ApplicationAccount()
                        .setApplication(applicationNode));
        addToOutput(export, output);
        addToOutput(applicationNode, output);
    }

    private void assembleOsInfo(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Identity registeredOwnerNode = new BlankIdentityNode();
        registeredOwnerNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_OWNER));
        Identity registeredOrganizationNode = new BlankIdentityNode();
        registeredOrganizationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ORGANIZATION));

        OperatingSystem operatingSystem = new OperatingSystem()
                .setInstallDate(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME))
                .setVersion(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VERSION));
        operatingSystem.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME));

        EnvironmentVariable envVar = new EnvironmentVariable()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEMP_DIR));
        envVar.setName("TEMP");
        Trace tempDirectoryNode = new BlankTraceNode()
                .addBundle(envVar);

        Trace export = new Trace(uuid)
                .addBundle(operatingSystem)
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new Device()
                        .setSerialNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PRODUCT_ID)))
                .addBundle(new ComputerSpecification()
                        .setHostName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME))
                        .setProcessorArchitecture(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROCESSOR_ARCHITECTURE)))
                .addBundle(new WindowsComputerSpecification()
                        .setRegisteredOrganization(registeredOrganizationNode)
                        .setRegisteredOwner(registeredOwnerNode)
                        .setWindowsTempDirectory(tempDirectoryNode));

        addToOutput(export, output);
        addToOutput(registeredOwnerNode, output);
        addToOutput(registeredOrganizationNode, output);
        addToOutput(tempDirectoryNode, output);
    }

    private void assembleOsAccount(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL)))
                .addBundle(new PathRelation()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addBundle(new WindowsAccount()
                        .setGroups(getValueIfPresent(artifact, StandardAttributeTypes.TSK_GROUPS)));

        export.setTag(getValueIfPresent(artifact, StandardAttributeTypes.TSK_FLAG));

        DigitalAccount digitalAccount = new DigitalAccount()
                .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DISPLAY_NAME))
                .setLastLoginTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_ACCESSED));
        digitalAccount.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        export.addBundle(digitalAccount);

        Identity ownerNode = new BlankIdentityNode();
        ownerNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        Account account = new Account()
                .setAccountType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ACCOUNT_TYPE))
                .setOwner(ownerNode)
                .setAccountIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_ID));
        account.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));

        export.addBundle(account);

        addToOutput(export, output);
        addToOutput(ownerNode, output);
    }

    private void assembleServiceAccount(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace inReplyToNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_REPLYTO)));

        Trace export = new Trace(uuid)
                .addBundle(new Account()
                        .setAccountType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_CATEGORY)))
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new EmailMessage()
                        .setInReplyTo(inReplyToNode))
                .addBundle(new DigitalAccount()
                        .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)))
                .addBundle(new AccountAuthentication()
                        .setPassword(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PASSWORD)))
                .addBundle(new PathRelation()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new DigitalAccount()
                        .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_NAME)));

        export.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        ApplicationAccount account = new ApplicationAccount()
                .setApplication(applicationNode);
        account.setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_ID));
        account.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        export.addBundle(account);

        addToOutput(export, output);
        addToOutput(applicationNode, output);
        addToOutput(inReplyToNode, output);
    }

    private void assembleContact(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        EmailAddress homeAddress = new EmailAddress()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_HOME));
        homeAddress.setTag("Home");

        EmailAddress workAddress = new EmailAddress()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_OFFICE));
        workAddress.setTag("Work");

        PhoneAccount homePhone = new PhoneAccount()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_HOME));
        homePhone.setTag("Home");

        PhoneAccount workPhone = new PhoneAccount()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_OFFICE));
        workPhone.setTag("Work");

        PhoneAccount mobilePhone = new PhoneAccount()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_MOBILE));
        mobilePhone.setTag("Mobile");

        Trace export = new Trace(uuid)
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL)))
                .addBundle(homeAddress)
                .addBundle(workAddress)
                .addBundle(new Contact()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)))
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addBundle(homePhone)
                .addBundle(workPhone)
                .addBundle(mobilePhone);
        addToOutput(export, output);
    }

    private void assembleMessage(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException, BlackboardJsonAttrUtil.InvalidJsonException {
        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MESSAGE_TYPE)));

        Trace senderNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_FROM)));

        Trace fromNode = new BlankTraceNode()
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_FROM)));

        Trace toNode = new BlankTraceNode()
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_TO)));

        Trace export = new Trace(uuid)
                .addBundle(new Message()
                        .setMessageText(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT))
                        .setApplication(applicationNode)
                        .setSentTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME))
                        .setMessageType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DIRECTION))
                        .setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_THREAD_ID)))
                .addBundle(new EmailMessage()
                        .setSender(senderNode))
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addBundle(new PhoneCall()
                        .setFrom(fromNode)
                        .setTo(toNode))
                .addBundle(new SMSMessage()
                        .setIsRead(getIntegerIfPresent(artifact, StandardAttributeTypes.TSK_READ_STATUS)));

        BlackboardAttribute attachments = artifact.getAttribute(StandardAttributeTypes.TSK_ATTACHMENTS);
        if (attachments != null) {
            MessageAttachments attachmentsContainer = BlackboardJsonAttrUtil.fromAttribute(attachments, MessageAttachments.class);
            List<MessageAttachments.Attachment> tskAttachments = new ArrayList<>();
            tskAttachments.addAll(attachmentsContainer.getUrlAttachments());
            tskAttachments.addAll(attachmentsContainer.getFileAttachments());

            tskAttachments.forEach((tskAttachment) -> {
                export.addBundle(new Attachment()
                        .setUrl(tskAttachment.getLocation())
                );
            });
        }

        addToOutput(export, output);
        addToOutput(applicationNode, output);
        addToOutput(senderNode, output);
        addToOutput(fromNode, output);
        addToOutput(toNode, output);
    }

    private void assembleMetadataExif(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Device()
                        .setManufacturer(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MAKE))
                        .setModel(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MODEL)))
                .addBundle(new LatLongCoordinates()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        addToOutput(export, output);
    }

    private void assembleCallog(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace fromNode = new BlankTraceNode()
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_FROM)));

        Trace toNode = new BlankTraceNode()
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_TO)));

        Trace export = new Trace(uuid)
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addBundle(new PhoneCall()
                        .setFrom(fromNode)
                        .setTo(toNode)
                        .setEndTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END))
                        .setStartTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                        .setCallType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DIRECTION)))
                .addBundle(new Contact()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)));

        addToOutput(export, output);
        addToOutput(toNode, output);
        addToOutput(fromNode, output);
    }

    private void assembleCalendarEntry(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid);

        CalendarEntry calendarEntry = new CalendarEntry()
                .setStartTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                .setEndTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END))
                .setEventType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_CALENDAR_ENTRY_TYPE));

        calendarEntry.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));

        calendarEntry.setLocation(locationNode);
        export.addBundle(calendarEntry);

        addToOutput(export, output);
        addToOutput(locationNode, output);
    }

    private void assembleSpeedDialEntry(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Contact()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME_PERSON)))
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)));

        addToOutput(export, output);
    }

    private void assembleBluetoothPairing(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new MobileDevice()
                        .setBluetoothDeviceName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_NAME)))
                .addBundle(new MACAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        addToOutput(export, output);
    }

    private void assembleGpsBookmark(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new LatLongCoordinates()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)))
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        SimpleAddress simpleAddress = new SimpleAddress();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
        export.addBundle(simpleAddress);

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        addToOutput(export, output);
    }

    private void assembleGpsLastKnownLocation(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new LatLongCoordinates()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        SimpleAddress simpleAddress = new SimpleAddress();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
        export.addBundle(simpleAddress);

        addToOutput(export, output);
        addToOutput(locationNode, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(locationNode.getId())
                .setTarget(export.getId()), output);
    }

    private void assembleGpsSearch(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new LatLongCoordinates()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        SimpleAddress simpleAddress = new SimpleAddress();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
        export.addBundle(simpleAddress);

        addToOutput(export, output);
        addToOutput(locationNode, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(locationNode.getId())
                .setTarget(export.getId()), output);
    }

    private void assembleProgRun(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME))
                        .setNumberOfLaunches(getIntegerIfPresent(artifact, StandardAttributeTypes.TSK_COUNT)));

        addToOutput(export, output);
    }

    private void assembleEncryptionDetected(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid)
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        addToOutput(export, output);
    }

    private void assembleInterestingArtifact(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        Long associatedArtifactId = getLongIfPresent(artifact, StandardAttributeTypes.TSK_ASSOCIATED_ARTIFACT);
        if (associatedArtifactId != null) {
            BlackboardArtifact associatedArtifact = artifact.getSleuthkitCase().getBlackboardArtifact(associatedArtifactId);

            addToOutput(new BlankRelationshipNode()
                    .setSource(export.getId())
                    .setTarget(this.uuidService.createUUID(associatedArtifact)), output);
        }

        addToOutput(export, output);
    }

    private void assembleGPSRoute(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        SimpleAddress simpleAddress = new SimpleAddress();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
        export.addBundle(simpleAddress);

        Location location = new BlankLocationNode();
        location.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        addToOutput(export, output);
        addToOutput(location, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(location.getId())
                .setTarget(export.getId()), output);
    }

    private void assembleRemoteDrive(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new PathRelation()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_REMOTE_PATH)))
                .addBundle(new PathRelation()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCAL_PATH)));

        addToOutput(export, output);
    }

    private void assembleAccount(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Account account = new Account()
                .setAccountType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ACCOUNT_TYPE))
                .setAccountIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ID));

        Account creditCardAccount = new Account()
                .setAccountIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_CARD_NUMBER));

        creditCardAccount.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        Trace export = new Trace(uuid)
                .addBundle(account)
                .addBundle(creditCardAccount);

        addToOutput(export, output);
    }

    private void assembleEncryptionSuspected(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid)
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        addToOutput(export, output);
    }

    private void assembleObjectDetected(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid)
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        export.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        addToOutput(export, output);
    }

    private void assembleWifiNetwork(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        WirelessNetworkConnection wirelessNetwork = new WirelessNetworkConnection()
                .setSSID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SSID));

        wirelessNetwork.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        String networkId = getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_ID);
        if (networkId != null) {
            wirelessNetwork.setId("_:" + networkId);
        }

        Trace export = new Trace(uuid)
                .addBundle(wirelessNetwork);

        addToOutput(export, output);
    }

    private void assembleDeviceInfo(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new MobileDevice()
                        .setIMEI(getValueIfPresent(artifact, StandardAttributeTypes.TSK_IMEI)))
                .addBundle(new SIMCard()
                        .setICCID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ICCID))
                        .setIMSI(getValueIfPresent(artifact, StandardAttributeTypes.TSK_IMSI)));

        addToOutput(export, output);
    }

    private void assembleSimAttached(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new SIMCard()
                        .setICCID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ICCID))
                        .setIMSI(getValueIfPresent(artifact, StandardAttributeTypes.TSK_IMSI)));

        addToOutput(export, output);
    }

    private void assembleBluetoothAdapter(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new MACAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));

        addToOutput(export, output);
    }

    private void assembleWifiNetworkAdapter(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new MACAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));

        addToOutput(export, output);
    }

    private void assembleVerificationFailed(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        addToOutput(export, output);
    }

    private void assembleDataSourceUsage(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid);
        export.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        addToOutput(export, output);
    }

    private void assembleWebFormAddress(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        SimpleAddress simpleAddress = new SimpleAddress();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));

        Trace export = new Trace(uuid)
                .addBundle(simpleAddress)
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL)))
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)));

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_ACCESSED));
        export.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_MODIFIED));

        Person person = new BlankPersonNode();
        person.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME_PERSON));

        addToOutput(export, output);
        addToOutput(person, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(person.getId())
                .setTarget(export.getId()), output);

    }

    private void assembleWebCache(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new PathRelation()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new HTTPConnection()
                        .setHttpRequestHeader(getValueIfPresent(artifact, StandardAttributeTypes.TSK_HEADERS)));

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));

        addToOutput(export, output);
    }

    private void assembleTimelineEvent(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Action export = new Action(uuid)
                .setStartTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        export.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        Long eventType = getLongIfPresent(artifact, StandardAttributeTypes.TSK_TL_EVENT_TYPE);
        if (eventType != null) {
            Optional<TimelineEventType> timelineEventType = artifact.getSleuthkitCase()
                    .getTimelineManager()
                    .getEventType(eventType);
            if (timelineEventType.isPresent()) {
                Trace actionArg = new BlankTraceNode()
                        .addBundle(new ActionArgument()
                                .setArgumentName(timelineEventType.get().getDisplayName()));

                addToOutput(actionArg, output);
                addToOutput(new BlankRelationshipNode()
                        .setSource(actionArg.getId())
                        .setTarget(export.getId()), output);
            }
        }

        addToOutput(export, output);
    }

    private void assembleClipboardContent(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Note()
                        .setText(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT)));

        addToOutput(export, output);
    }

    private void assembleAssociatedObject(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid);
        addToOutput(export, output);

        BlackboardAttribute associatedArtifactID = artifact.getAttribute(StandardAttributeTypes.TSK_ASSOCIATED_ARTIFACT);
        if (associatedArtifactID != null) {
            long artifactID = associatedArtifactID.getValueLong();
            BlackboardArtifact associatedArtifact = artifact.getSleuthkitCase().getArtifactByArtifactId(artifactID);
            if (associatedArtifact != null) {
                addToOutput(new BlankRelationshipNode()
                        .setSource(uuid)
                        .setTarget(this.uuidService.createUUID(associatedArtifact)), output);
            }
        }
    }

    private void assembleUserContentSuspected(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        addToOutput(export, output);
    }

    private void assembleMetadata(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME))
                        .setVersion(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VERSION)));

        ContentData contentData = new ContentData();
        contentData.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        contentData.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_MODIFIED));
        contentData.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        Identity owner = new BlankIdentityNode();
        owner.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_OWNER));
        contentData.setOwner(owner);
        export.addBundle(contentData);

        ContentData contentDataTwo = new ContentData();
        contentDataTwo.setTag("Last Printed");
        contentDataTwo.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_LAST_PRINTED_DATETIME));
        export.addBundle(contentDataTwo);

        Organization organization = new BlankOrganizationNode();
        organization.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ORGANIZATION));

        Identity lastAuthor = new BlankIdentityNode();
        lastAuthor.setTag("Last Author");
        lastAuthor.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_ID));

        addToOutput(export, output);
        addToOutput(owner, output);
        addToOutput(organization, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(organization.getId())
                .setTarget(export.getId()), output);
        addToOutput(lastAuthor, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(lastAuthor.getId())
                .setTarget(export.getId()), output);
    }

    private void assembleGpsTrack(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException, BlackboardJsonAttrUtil.InvalidJsonException {
        Trace export = new Trace(uuid)
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        BlackboardAttribute trackpoints = artifact.getAttribute(StandardAttributeTypes.TSK_GEO_TRACKPOINTS);
        if (trackpoints != null) {
            GeoTrackPoints points = BlackboardJsonAttrUtil.fromAttribute(trackpoints, GeoTrackPoints.class);
            for (GeoTrackPoints.TrackPoint point : points) {
                export.addBundle(new LatLongCoordinates()
                        .setAltitude(point.getAltitude())
                        .setLatitude(point.getLatitude())
                        .setLongitude(point.getLongitude()));
            }
        }

        addToOutput(export, output);
    }

    /**
     * Pulls the attribute type from the artifact and returns its value if
     * present. Should only be called on BlackboardAttribute types that hold
     * integer values.
     */
    private Integer getIntegerIfPresent(BlackboardArtifact artifact, BlackboardAttribute.Type type) throws TskCoreException {
        if (artifact.getAttribute(type) != null) {
            return artifact.getAttribute(type).getValueInt();
        } else {
            return null;
        }
    }

    /**
     * Pulls the attribute type from the artifact and returns its value if
     * present. Should only be called on BlackboardAttribute types that hold
     * double values.
     */
    private Double getDoubleIfPresent(BlackboardArtifact artifact, BlackboardAttribute.Type type) throws TskCoreException {
        if (artifact.getAttribute(type) != null) {
            return artifact.getAttribute(type).getValueDouble();
        } else {
            return null;
        }
    }

    /**
     * Pulls the attribute type from the artifact and returns its value if
     * present. Should only be called on BlackboardAttribute types that hold
     * long values.
     */
    private Long getLongIfPresent(BlackboardArtifact artifact, BlackboardAttribute.Type type) throws TskCoreException {
        if (artifact.getAttribute(type) != null) {
            return artifact.getAttribute(type).getValueLong();
        } else {
            return null;
        }
    }

    /**
     * Pulls the attribute type from the artifact and returns its value as a
     * string if present. This operation is valid for all attribute types.
     */
    private String getValueIfPresent(BlackboardArtifact artifact, BlackboardAttribute.Type type) throws TskCoreException {
        if (artifact.getAttribute(type) != null) {
            return artifact.getAttribute(type).getDisplayString();
        } else {
            return null;
        }
    }

    /**
     * Add the parent-child relationship, if configured to do so.
     */
    private void addParentChildRelationship(List<JsonElement> output, String sourceId, String parentId) {
        String parentChildProperty = this.props.getProperty(INCLUDE_PARENT_CHILD_RELATIONSHIPS_PROP,
                DEFAULT_PARENT_CHILD_RELATIONSHIPS_VALUE);

        if (Boolean.valueOf(parentChildProperty)) {
            addToOutput(new BlankRelationshipNode()
                    .setSource(sourceId)
                    .setTarget(parentId)
                    .setKindOfRelationship("contained-within")
                    .isDirectional(true), output);
        }
    }

    /**
     * Adds a given CASE export object to the JSON output that will be consumed
     * by the client.
     */
    private void addToOutput(UcoObject ucoObject, List<JsonElement> output) {
        output.add(gson.toJsonTree(ucoObject));
    }
}
