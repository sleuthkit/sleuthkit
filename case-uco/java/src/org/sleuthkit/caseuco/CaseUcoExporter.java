/*
 * Sleuth Kit CASE JSON LD Support
 *
 * Copyright 2020 Basis Technology Corp.
 * ContactFacet: carrier <at> sleuthkit <dot> org
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

        ObservableObject export = new ObservableObject(this.uuidService.createUUID(sleuthkitCase));

        if (sleuthkitCase.getDatabaseType().equals(DbType.POSTGRESQL)) {
            export.addFacet(new FileFacet()
                    .setFilePath(caseDirPath)
                    .setIsDirectory(true));
        } else {
            export.addFacet(new FileFacet()
                    .setFilePath(caseDirPath + "/" + sleuthkitCase.getDatabaseName())
                    .setIsDirectory(false));
        }

        serializeObjectToOutput(export, output);
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

        ContentDataFacet contentData = new ContentDataFacet()
                .setMimeType(file.getMIMEType())
                .setSizeInBytes(file.getSize())
                .setComment()
                .setMd5Hash(file.getMd5Hash());

        if (localPath != null) {
            ObservableObject localPathTrace = new BlankObservableObject()
                    .addFacet(new URLFacet()
                            .setFullValue(localPath));
            contentData.setDataPayloadReferenceUrl(localPathTrace);

            serializeObjectToOutput(localPathTrace, output);
        }

        FileFacet fileExport = new FileFacet()
                .setAccessedTime(file.getAtime())
                .setExtension(file.getNameExtension())
                .setFileName(file.getName())
                .setFilePath(file.getUniquePath())
                .setIsDirectory(file.isDir())
                .setSizeInBytes(file.getSize());
        fileExport.setModifiedTime(file.getMtime());
        fileExport.setCreatedTime(file.getCrtime());

        ObservableObject export = new ObservableObject(this.uuidService.createUUID(file))
                .addFacet(contentData)
                .addFacet(fileExport);

        serializeObjectToOutput(export, output);
        addParentChildRelationshipToOutput(output, export.getId(),
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

        serializeObjectToOutput(annotation, output);
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

        ObservableObject export = new ObservableObject(this.uuidService.createUUID(dataSource))
                .addFacet(new FileFacet()
                        .setFilePath(getDataSourcePath(dataSource)))
                .addFacet(new ContentDataFacet()
                        .setSizeInBytes(dataSource.getSize()));

        serializeObjectToOutput(export, output);
        addParentChildRelationshipToOutput(output, export.getId(),
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
     * Exports a FileSystemFacet instance to CASE.
     *
     * @param fileSystem FileSystemFacet instance to export
     * @return A collection of CASE JSON elements
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportFileSystem(FileSystem fileSystem) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        ObservableObject export = new ObservableObject(this.uuidService.createUUID(fileSystem))
                .addFacet(new org.sleuthkit.caseuco.FileSystemFacet()
                        .setFileSystemType(fileSystem.getFsType())
                        .setCluserSize(fileSystem.getBlock_size()));

        serializeObjectToOutput(export, output);
        addParentChildRelationshipToOutput(output, export.getId(),
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

        ObservableObject export = new ObservableObject(this.uuidService.createUUID(pool))
                .addFacet(new ContentDataFacet()
                        .setSizeInBytes(pool.getSize()));

        serializeObjectToOutput(export, output);
        addParentChildRelationshipToOutput(output, export.getId(),
                this.uuidService.createUUID(pool.getParent()));

        return output;
    }

    /**
     * Exports a VolumeFacet instance to CASE.
     *
     * @param volume VolumeFacet instance to export
     * @return A collection of CASE JSON elements
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportVolume(Volume volume) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        ObservableObject export = new ObservableObject(this.uuidService.createUUID(volume));
        org.sleuthkit.caseuco.VolumeFacet volumeFacet = new org.sleuthkit.caseuco.VolumeFacet();
        if (volume.getLength() > 0) {
            volumeFacet.setSectorSize(volume.getSize() / volume.getLength());
        }
        export.addFacet(volumeFacet)
                .addFacet(new ContentDataFacet()
                        .setSizeInBytes(volume.getSize()));

        serializeObjectToOutput(export, output);
        addParentChildRelationshipToOutput(output, export.getId(),
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

        ObservableObject export = new ObservableObject(this.uuidService.createUUID(volumeSystem))
                .addFacet(new ContentDataFacet()
                        .setSizeInBytes(volumeSystem.getSize()));

        serializeObjectToOutput(export, output);
        addParentChildRelationshipToOutput(output, export.getId(),
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
    @SuppressWarnings( "deprecation" )
    public List<JsonElement> exportBlackboardArtifact(BlackboardArtifact artifact) throws TskCoreException,
            ContentNotExportableException, BlackboardJsonAttrUtil.InvalidJsonException {
        List<JsonElement> output = new ArrayList<>();

        String uuid = this.uuidService.createUUID(artifact);
        int artifactTypeId = artifact.getArtifactTypeID();

        // NOTE: The following methods will add JSON to the 
        // passed in 'output' list
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
            assembleCallLog(uuid, artifact, output);
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

        // Test if we did not have the artifact OR if the 
        // assemble method did not populate the passed in 'output'
        if (output.isEmpty()) {
            throw new ContentNotExportableException(String.format(
                    "Artifact [id:%d, type:%d] is either not supported "
                    + "or did not have any exported attributes.", artifact.getId(), artifactTypeId));
        }

        addParentChildRelationshipToOutput(output, uuid,
                this.uuidService.createUUID(artifact.getParent()));

        return output;
    }

    private void assembleWebCookie(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new URLFacet()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addFacet(new ContentDataFacet()
                        .setDataPayload(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VALUE)));
         

        ObservableObject cookieDomainNode = new BlankObservableObject()
                .addFacet(new DomainNameFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)));

        ObservableObject applicationNode = new BlankObservableObject()
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        BrowserCookieFacet cookie = new BrowserCookieFacet()
                .setCookieName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME))
                .setCookieDomain(cookieDomainNode)
                .setApplication(applicationNode)
                .setAccessedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                .setExpirationTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END));
        cookie.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));

        export.addFacet(cookie);

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(cookieDomainNode, output);
        serializeObjectToOutput(applicationNode, output);
    }

    private void assembleWebBookmark(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject applicationNode = new BlankObservableObject()
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        BrowserBookmarkFacet bookmark = new BrowserBookmarkFacet()
                .setUrlTargeted(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL))
                .setApplication(applicationNode);
        bookmark.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        bookmark.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(bookmark)
                .addFacet(new DomainNameFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)));
         

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(applicationNode, output);
    }

    private void assembleGenInfo(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Hash hash = new Hash(uuid, getValueIfPresent(artifact, StandardAttributeTypes.TSK_HASH_PHOTODNA));
        serializeObjectToOutput(hash, output);
    }

    private void assembleWebHistory(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject userNameNode = new BlankObservableObject();

        IdentityFacet identityFacet = new IdentityFacet();
        identityFacet.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_NAME));
        userNameNode.addFacet(identityFacet);

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new URLHistoryFacet()
                        .setBrowserInformation(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME))
                        .setUrlHistoryEntry(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addFacet(new DomainNameFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)))
                .addFacet(identityFacet);
                         
         

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(userNameNode, output);
    }

    private void assembleWebDownload(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new URLFacet()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addFacet(new DomainNameFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addFacet(new FileFacet()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        serializeObjectToOutput(export, output);
    }

    private void assembleDeviceAttached(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new DeviceFacet()
                        .setManufacturer(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MAKE))
                        .setModel(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MODEL))
                        .setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_ID)))
                .addFacet(new MACAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));
         

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        serializeObjectToOutput(export, output);
    }

    private void assembleHashsetHit(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        serializeObjectToOutput(export, output);
    }

    private void assembleInstalledProg(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new FileFacet()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH_SOURCE)));
         
        SoftwareFacet software = new SoftwareFacet();
        software.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME));
        export.addFacet(software);

        FileFacet file = new FileFacet()
                .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH));
        file.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        file.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        export.addFacet(file);

        serializeObjectToOutput(export, output);
    }

    private void assembleRecentObject(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
         

        FileFacet file = new FileFacet()
                .setAccessedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_ACCESSED));
        file.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        export.addFacet(file);

        serializeObjectToOutput(export, output);

        Assertion assertion = new BlankAssertionNode()
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        serializeObjectToOutput(assertion, output);
        serializeObjectToOutput(new BlankRelationshipNode()
                .setSource(assertion.getId())
                .setTarget(uuid), output);
    }

    private void assembleInterestingFileHit(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        serializeObjectToOutput(export, output);
    }

    private void assembleExtractedText(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new ExtractedStringsFacet()
                        .setStringValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT)));
        serializeObjectToOutput(export, output);
    }

    private void assembleEmailMessage(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject bccNode = new BlankObservableObject()
                .addFacet(new EmailAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_BCC)));

        ObservableObject ccNode = new BlankObservableObject()
                .addFacet(new EmailAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CC)));

        ObservableObject fromNode = new BlankObservableObject()
                .addFacet(new EmailAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_FROM)));

        ObservableObject headerRawNode = new BlankObservableObject()
                .addFacet(new ExtractedStringsFacet()
                        .setStringValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_HEADERS)));

        EmailMessageFacet emailMessage = new EmailMessageFacet();
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

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(emailMessage
                        .setReceivedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_RCVD))
                        .setSentTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_SENT))
                        .setBcc(bccNode)
                        .setCc(ccNode)
                        .setFrom(fromNode)
                        .setHeaderRaw(headerRawNode)
                        .setMessageID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MSG_ID))
                        .setSubject(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SUBJECT)))
                .addFacet(new FileFacet()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)));
         

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(bccNode, output);
        serializeObjectToOutput(ccNode, output);
        serializeObjectToOutput(fromNode, output);
        serializeObjectToOutput(headerRawNode, output);
    }

    private void assembleWebSearchQuery(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject applicationNode = new BlankObservableObject()
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new NoteFacet()
                        .setText(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT)))
                .addFacet(new DomainFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addFacet(new ApplicationAccountFacet()
                        .setApplication(applicationNode));
        serializeObjectToOutput(export, output);
        serializeObjectToOutput(applicationNode, output);
    }

    private void assembleOsInfo(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Identity registeredOwnerNode = new BlankIdentityNode();
        registeredOwnerNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_OWNER));
        Identity registeredOrganizationNode = new BlankIdentityNode();
        registeredOrganizationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ORGANIZATION));

        OperatingSystemFacet operatingSystem = new OperatingSystemFacet()
                .setInstallDate(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME))
                .setVersion(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VERSION));
        operatingSystem.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME));

        EnvironmentVariableFacet envVar = new EnvironmentVariableFacet()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEMP_DIR));
        envVar.setName("TEMP");
        ObservableObject tempDirectoryNode = new BlankObservableObject()
                .addFacet(envVar);

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(operatingSystem)
                .addFacet(new DomainNameFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addFacet(new DeviceFacet()
                        .setSerialNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PRODUCT_ID)))
                .addFacet(new ComputerSpecificationFacet()
                        .setHostName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME))
                        .setProcessorArchitecture(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROCESSOR_ARCHITECTURE)))
                .addFacet(new WindowsComputerSpecificationFacet()
                        .setRegisteredOrganization(registeredOrganizationNode)
                        .setRegisteredOwner(registeredOwnerNode)
                        .setWindowsTempDirectory(tempDirectoryNode));
         

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(registeredOwnerNode, output);
        serializeObjectToOutput(registeredOrganizationNode, output);
        serializeObjectToOutput(tempDirectoryNode, output);
    }

    private void assembleOsAccount(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new EmailAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL)))
                .addFacet(new PathRelationFacet()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addFacet(new WindowsAccountFacet()
                        .setGroups(getValueIfPresent(artifact, StandardAttributeTypes.TSK_GROUPS)));
         

        export.setTag(getValueIfPresent(artifact, StandardAttributeTypes.TSK_FLAG));

        DigitalAccountFacet digitalAccount = new DigitalAccountFacet()
                .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DISPLAY_NAME))
                .setLastLoginTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_ACCESSED));
        digitalAccount.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        export.addFacet(digitalAccount);

        Identity ownerNode = new BlankIdentityNode();
        ownerNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        AccountFacet account = new AccountFacet()
                .setAccountType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ACCOUNT_TYPE))
                .setOwner(ownerNode)
                .setAccountIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_ID));
        account.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));

        export.addFacet(account);

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(ownerNode, output);
    }

    private void assembleServiceAccount(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject inReplyToNode = new BlankObservableObject()
                .addFacet(new EmailAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_REPLYTO)));

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new AccountFacet()
                        .setAccountType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_CATEGORY)))
                .addFacet(new DomainNameFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addFacet(new EmailMessageFacet()
                        .setInReplyTo(inReplyToNode))
                .addFacet(new DigitalAccountFacet()
                        .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)))
                .addFacet(new AccountAuthenticationFacet()
                        .setPassword(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PASSWORD)))
                .addFacet(new PathRelationFacet()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addFacet(new URLFacet()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addFacet(new DigitalAccountFacet()
                        .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_NAME)));
         

        export.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        ObservableObject applicationNode = new BlankObservableObject()
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));

        ApplicationAccountFacet account = new ApplicationAccountFacet()
                .setApplication(applicationNode);
        account.setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_ID));
        account.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        export.addFacet(account);

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(applicationNode, output);
        serializeObjectToOutput(inReplyToNode, output);
    }

    private void assembleContact(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        EmailAddressFacet homeAddress = new EmailAddressFacet()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_HOME));
        homeAddress.setTag("Home");

        EmailAddressFacet workAddress = new EmailAddressFacet()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_OFFICE));
        workAddress.setTag("Work");

        PhoneAccountFacet homePhone = new PhoneAccountFacet()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_HOME));
        homePhone.setTag("Home");

        PhoneAccountFacet workPhone = new PhoneAccountFacet()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_OFFICE));
        workPhone.setTag("Work");

        PhoneAccountFacet mobilePhone = new PhoneAccountFacet()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_MOBILE));
        mobilePhone.setTag("Mobile");

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new URLFacet()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addFacet(new EmailAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL)))
                .addFacet(homeAddress)
                .addFacet(workAddress)
                .addFacet(new ContactFacet()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)))
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addFacet(homePhone)
                .addFacet(workPhone)
                .addFacet(mobilePhone);

        serializeObjectToOutput(export, output);
    }

    private void assembleMessage(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException, BlackboardJsonAttrUtil.InvalidJsonException {
        ObservableObject applicationNode = new BlankObservableObject()
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MESSAGE_TYPE)));

        ObservableObject senderNode = new BlankObservableObject()
                .addFacet(new EmailAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_FROM)));

        ObservableObject fromNode = new BlankObservableObject()
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_FROM)));

        ObservableObject toNode = new BlankObservableObject()
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_TO)));

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new MessageFacet()
                        .setMessageText(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT))
                        .setApplication(applicationNode)
                        .setSentTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME))
                        .setMessageType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DIRECTION))
                        .setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_THREAD_ID)))
                .addFacet(new EmailMessageFacet()
                        .setSender(senderNode))
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addFacet(new PhoneCallFacet()
                        .setFrom(fromNode)
                        .setTo(toNode))
                .addFacet(new SMSMessageFacet()
                        .setIsRead(getIntegerIfPresent(artifact, StandardAttributeTypes.TSK_READ_STATUS)));
         

        BlackboardAttribute attachments = artifact.getAttribute(StandardAttributeTypes.TSK_ATTACHMENTS);
        if (attachments != null) {
            MessageAttachments attachmentsContainer = BlackboardJsonAttrUtil.fromAttribute(attachments, MessageAttachments.class);
            List<MessageAttachments.Attachment> tskAttachments = new ArrayList<>();
            tskAttachments.addAll(attachmentsContainer.getUrlAttachments());
            tskAttachments.addAll(attachmentsContainer.getFileAttachments());

            tskAttachments.forEach((tskAttachment) -> {
                export.addFacet(new AttachmentFacet()
                        .setUrl(tskAttachment.getLocation())
                );
            });
        }

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(applicationNode, output);
        serializeObjectToOutput(senderNode, output);
        serializeObjectToOutput(fromNode, output);
        serializeObjectToOutput(toNode, output);
    }

    private void assembleMetadataExif(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new DeviceFacet()
                        .setManufacturer(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MAKE))
                        .setModel(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MODEL)))
                .addFacet(new LatLongCoordinatesFacet()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));
         

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        serializeObjectToOutput(export, output);
    }

    private void assembleCallLog(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject fromNode = new BlankObservableObject()
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_FROM)));

        ObservableObject toNode = new BlankObservableObject()
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_TO)));

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addFacet(new PhoneCallFacet()
                        .setFrom(fromNode)
                        .setTo(toNode)
                        .setEndTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END))
                        .setStartTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                        .setCallType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DIRECTION)))
                .addFacet(new ContactFacet()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)));
         

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(toNode, output);
        serializeObjectToOutput(fromNode, output);
    }

    private void assembleCalendarEntry(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid);
         

        CalendarEntryFacet calendarEntry = new CalendarEntryFacet()
                .setStartTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                .setEndTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END))
                .setEventType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_CALENDAR_ENTRY_TYPE));

        calendarEntry.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));

        calendarEntry.setLocation(locationNode);
        export.addFacet(calendarEntry);

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(locationNode, output);
    }

    private void assembleSpeedDialEntry(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new ContactFacet()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME_PERSON)))
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)));
         

        serializeObjectToOutput(export, output);
    }

    private void assembleBluetoothPairing(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new MobileDeviceFacet()
                        .setBluetoothDeviceName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_NAME)))
                .addFacet(new MACAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));
         

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        serializeObjectToOutput(export, output);
    }

    private void assembleGpsBookmark(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new LatLongCoordinatesFacet()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)))
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
                       

        SimpleAddressFacet simpleAddress = new SimpleAddressFacet();
        if (getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION) != null) {
            simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
            export.addFacet(simpleAddress);
        }

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        serializeObjectToOutput(export, output);
    }

    private void assembleGpsLastKnownLocation(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new LatLongCoordinatesFacet()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));
         
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        SimpleAddressFacet simpleAddress = new SimpleAddressFacet();
        if (getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION) != null) {
            simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
            export.addFacet(simpleAddress);
        }
        
        serializeObjectToOutput(export, output);
        serializeObjectToOutput(locationNode, output);
        serializeObjectToOutput(new BlankRelationshipNode()
                .setSource(locationNode.getId())
                .setTarget(export.getId()), output);
    }

    private void assembleGpsSearch(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new LatLongCoordinatesFacet()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));
         
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        SimpleAddressFacet simpleAddress = new SimpleAddressFacet();
        
        if (getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION) != null) {
            simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
            export.addFacet(simpleAddress);
        }

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(locationNode, output);
        serializeObjectToOutput(new BlankRelationshipNode()
                .setSource(locationNode.getId())
                .setTarget(export.getId()), output);
    }

    private void assembleProgRun(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        
        String comment = getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT);
        ObservableObject export = new ObservableObject(uuid);
         
        if (comment.toLowerCase().contains("prefetch")) {
            export.addFacet(new WindowsPrefetchFacet()
                            .setApplicationFileName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME))
                            .setTimesExecuted(getIntegerIfPresent(artifact, StandardAttributeTypes.TSK_COUNT)));
            
        } else {
        
            export.addFacet(new ApplicationFacet()
                            .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME))
                            .setNumberOfLaunches(getIntegerIfPresent(artifact, StandardAttributeTypes.TSK_COUNT)));
        }

        serializeObjectToOutput(export, output);
    }

    private void assembleEncryptionDetected(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid)
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        serializeObjectToOutput(export, output);
    }

    private void assembleInterestingArtifact(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        Long associatedArtifactId = getLongIfPresent(artifact, StandardAttributeTypes.TSK_ASSOCIATED_ARTIFACT);
        if (associatedArtifactId != null) {
            BlackboardArtifact associatedArtifact = artifact.getSleuthkitCase().getBlackboardArtifact(associatedArtifactId);

            serializeObjectToOutput(new BlankRelationshipNode()
                    .setSource(export.getId())
                    .setTarget(this.uuidService.createUUID(associatedArtifact)), output);
        }

        serializeObjectToOutput(export, output);
    }

    private void assembleGPSRoute(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
         
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        SimpleAddressFacet simpleAddress = new SimpleAddressFacet();
        if (getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION) != null) {
            simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
            export.addFacet(simpleAddress);
        }

        Location location = new BlankLocationNode();
        location.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(location, output);
        serializeObjectToOutput(new BlankRelationshipNode()
                .setSource(location.getId())
                .setTarget(export.getId()), output);
    }

    private void assembleRemoteDrive(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new PathRelationFacet()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_REMOTE_PATH)))
                .addFacet(new PathRelationFacet()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCAL_PATH)));
         

        serializeObjectToOutput(export, output);
    }

    private void assembleAccount(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        AccountFacet account = new AccountFacet()
                .setAccountType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ACCOUNT_TYPE))
                .setAccountIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ID));

        AccountFacet creditCardAccount = new AccountFacet()
                .setAccountIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_CARD_NUMBER));

        creditCardAccount.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(account)
                .addFacet(creditCardAccount);
         

        serializeObjectToOutput(export, output);
    }

    private void assembleEncryptionSuspected(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid)
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        serializeObjectToOutput(export, output);
    }

    private void assembleObjectDetected(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid)
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        export.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        serializeObjectToOutput(export, output);
    }

    private void assembleWifiNetwork(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        WirelessNetworkConnectionFacet wirelessNetwork = new WirelessNetworkConnectionFacet()
                .setSSID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SSID));

        wirelessNetwork.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));

        String networkId = getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_ID);
        if (networkId != null) {
            wirelessNetwork.setId("_:" + networkId);
        }

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(wirelessNetwork);
         

        serializeObjectToOutput(export, output);
    }

    private void assembleDeviceInfo(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new MobileDeviceFacet()
                        .setIMEI(getValueIfPresent(artifact, StandardAttributeTypes.TSK_IMEI)))
                .addFacet(new SIMCardFacet()
                        .setICCID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ICCID))
                        .setIMSI(getValueIfPresent(artifact, StandardAttributeTypes.TSK_IMSI)));
         

        serializeObjectToOutput(export, output);
    }

    private void assembleSimAttached(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new SIMCardFacet()
                        .setICCID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ICCID))
                        .setIMSI(getValueIfPresent(artifact, StandardAttributeTypes.TSK_IMSI)));
         

        serializeObjectToOutput(export, output);
    }

    private void assembleBluetoothAdapter(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new MACAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));
         

        serializeObjectToOutput(export, output);
    }

    private void assembleWifiNetworkAdapter(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new MACAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));
         

        serializeObjectToOutput(export, output);
    }

    private void assembleVerificationFailed(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        serializeObjectToOutput(export, output);
    }

    private void assembleDataSourceUsage(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid);
        export.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        serializeObjectToOutput(export, output);
    }

    private void assembleWebFormAddress(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        SimpleAddressFacet simpleAddress = new SimpleAddressFacet();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));

        ObservableObject export = new ObservableObject(uuid)
                .addFacet(simpleAddress)
                .addFacet(new EmailAddressFacet()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL)))
                .addFacet(new PhoneAccountFacet()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)));

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_ACCESSED));
        export.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_MODIFIED));

        Person person = new BlankPersonNode();
        person.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME_PERSON));

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(person, output);
        serializeObjectToOutput(new BlankRelationshipNode()
                .setSource(person.getId())
                .setTarget(export.getId()), output);

    }

    private void assembleWebCache(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new PathRelationFacet()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addFacet(new URLFacet()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addFacet(new HTTPConnectionFacet()
                        .setHttpRequestHeader(getValueIfPresent(artifact, StandardAttributeTypes.TSK_HEADERS)));
         

        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));

        serializeObjectToOutput(export, output);
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
                ObservableObject actionArg = new BlankObservableObject()
                        .addFacet(new ActionArgumentFacet()
                                .setArgumentName(timelineEventType.get().getDisplayName()));

                serializeObjectToOutput(actionArg, output);
                serializeObjectToOutput(new BlankRelationshipNode()
                        .setSource(actionArg.getId())
                        .setTarget(export.getId()), output);
            }
        }

        serializeObjectToOutput(export, output);
    }

    private void assembleClipboardContent(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new NoteFacet()
                        .setText(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT)));
         

        serializeObjectToOutput(export, output);
    }

    private void assembleAssociatedObject(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid);

        serializeObjectToOutput(export, output);

        Long associatedArtifactId = getLongIfPresent(artifact, StandardAttributeTypes.TSK_ASSOCIATED_ARTIFACT);
        if (associatedArtifactId != null) {
            BlackboardArtifact associatedArtifact = artifact.getSleuthkitCase().getBlackboardArtifact(associatedArtifactId);
            if (associatedArtifact != null) {
                serializeObjectToOutput(new BlankRelationshipNode()
                        .setSource(uuid)
                        .setTarget(this.uuidService.createUUID(associatedArtifact)), output);
            }
        }
    }

    private void assembleUserContentSuspected(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));

        serializeObjectToOutput(export, output);
    }

    private void assembleMetadata(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME))
                        .setVersion(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VERSION)));
         

        ContentDataFacet contentData = new ContentDataFacet();
        contentData.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        contentData.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_MODIFIED));
        contentData.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));

        Identity owner = new BlankIdentityNode();
        owner.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_OWNER));
        contentData.setOwner(owner);
        export.addFacet(contentData);

        ContentDataFacet contentDataTwo = new ContentDataFacet();
        contentDataTwo.setTag("Last Printed");
        contentDataTwo.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_LAST_PRINTED_DATETIME));
        export.addFacet(contentDataTwo);

        Organization organization = new BlankOrganizationNode();
        organization.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ORGANIZATION));

        Identity lastAuthor = new BlankIdentityNode();
        lastAuthor.setTag("Last Author");
        lastAuthor.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_ID));

        serializeObjectToOutput(export, output);
        serializeObjectToOutput(owner, output);
        serializeObjectToOutput(organization, output);
        serializeObjectToOutput(new BlankRelationshipNode()
                .setSource(organization.getId())
                .setTarget(export.getId()), output);
        serializeObjectToOutput(lastAuthor, output);
        serializeObjectToOutput(new BlankRelationshipNode()
                .setSource(lastAuthor.getId())
                .setTarget(export.getId()), output);
    }

    private void assembleGpsTrack(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException, BlackboardJsonAttrUtil.InvalidJsonException {
        ObservableObject export = new ObservableObject(uuid)
                .addFacet(new ApplicationFacet()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
         
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));

        BlackboardAttribute trackpoints = artifact.getAttribute(StandardAttributeTypes.TSK_GEO_TRACKPOINTS);
        if (trackpoints != null) {
            GeoTrackPoints points = BlackboardJsonAttrUtil.fromAttribute(trackpoints, GeoTrackPoints.class);
            for (GeoTrackPoints.TrackPoint point : points) {
                export.addFacet(new LatLongCoordinatesFacet()
                        .setAltitude(point.getAltitude())
                        .setLatitude(point.getLatitude())
                        .setLongitude(point.getLongitude()));
            }
        }

        serializeObjectToOutput(export, output);
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
     * Add a parent-child relationship entry to the 'output' list, if configured to do so.
     */
    private void addParentChildRelationshipToOutput(List<JsonElement> output, String childUuid, String parentUuid) {
        String parentChildProperty = this.props.getProperty(INCLUDE_PARENT_CHILD_RELATIONSHIPS_PROP,
                DEFAULT_PARENT_CHILD_RELATIONSHIPS_VALUE);

        if (Boolean.valueOf(parentChildProperty)) {
            serializeObjectToOutput(new BlankRelationshipNode()
                    .setSource(childUuid)
                    .setTarget(parentUuid)
                    .setKindOfRelationship("contained-within")
                    .isDirectional(true), output);
        }
    }

    /**
     * Adds a given CASE export object to the JSON output that will be consumed
     * by the client.
     */
    private void serializeObjectToOutput(UcoObject ucoObject, List<JsonElement> output) {
        output.add(gson.toJsonTree(ucoObject));
    }
}
