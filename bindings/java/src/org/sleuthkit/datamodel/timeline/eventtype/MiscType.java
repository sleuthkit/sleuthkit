/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel.timeline.eventtype;

import com.google.common.base.MoreObjects;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.function.Function;
import java.util.logging.Level;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;
import org.sleuthkit.datamodel.timeline.eventtype.ArtifactEventType.AttributeEventDescription;
import org.sleuthkit.datamodel.timeline.eventtype.ArtifactEventType.AttributeExtractor;
import org.sleuthkit.datamodel.timeline.eventtype.ArtifactEventType.EmptyExtractor;
import static org.sleuthkit.datamodel.timeline.eventtype.ArtifactEventType.getAttributeSafe;

/**
 *
 */
public final class MiscType extends AbstractEventType implements ArtifactEventType {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.eventtype.Bundle");  // NON-NLS

	public static final MiscType MESSAGE = new MiscType(BUNDLE.getString("MiscTypes.message.name"),// NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_MESSAGE),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE)),
			artf -> {
				final BlackboardAttribute dir = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DIRECTION));
				final BlackboardAttribute readStatus = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_READ_STATUS));
				final BlackboardAttribute name = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_NAME));
				final BlackboardAttribute phoneNumber = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER));
				final BlackboardAttribute subject = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_SUBJECT));
				List<String> asList = Arrays.asList(stringValueOf(dir),
						stringValueOf(readStatus),
						name == null && phoneNumber == null ? "" : toFrom(dir),
						stringValueOf(MoreObjects.firstNonNull(name, phoneNumber)),
						stringValueOf(subject)
				);
				return StringUtils.join(asList, " ");
			},
			new AttributeExtractor(
					new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_TEXT)));
	public static final MiscType GPS_ROUTE = new MiscType(BUNDLE.getString("MiscTypes.GPSRoutes.name"), // NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_GPS_ROUTE),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PROG_NAME)),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_LOCATION)),
			artf -> {
				final BlackboardAttribute latStart = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_LATITUDE_START));
				final BlackboardAttribute longStart = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE_START));
				final BlackboardAttribute latEnd = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_LATITUDE_END));
				final BlackboardAttribute longEnd = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE_END));
				return String.format("from %1$s %2$s to %3$s %4$s", stringValueOf(latStart), stringValueOf(longStart), stringValueOf(latEnd), stringValueOf(longEnd)); // NON-NLS
			});
	public static final MiscType GPS_TRACKPOINT = new MiscType(BUNDLE.getString("MiscTypes.GPSTrackpoint.name"), // NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_GPS_TRACKPOINT),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PROG_NAME)),
			artf -> {
				final BlackboardAttribute longitude = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE));
				final BlackboardAttribute latitude = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_LATITUDE));
				return stringValueOf(latitude) + " " + stringValueOf(longitude); // NON-NLS
			},
			new EmptyExtractor());
	public static final MiscType CALL_LOG = new MiscType(BUNDLE.getString("MiscTypes.Calls.name"), // NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_CALLLOG),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_START),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_NAME)),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER)),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DIRECTION)));
	public static final MiscType EMAIL = new MiscType(BUNDLE.getString("MiscTypes.Email.name"), // NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_EMAIL_MSG),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_SENT),
			artf -> {
				final BlackboardAttribute emailFrom = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_FROM));
				final BlackboardAttribute emailTo = getAttributeSafe(artf, new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_TO));
				return stringValueOf(emailFrom) + " to " + stringValueOf(emailTo); // NON-NLS
			},
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_SUBJECT)),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_PLAIN)));
	public static final MiscType RECENT_DOCUMENTS = new MiscType(BUNDLE.getString("MiscTypes.recentDocuments.name"), // NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_RECENT_OBJECT),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PATH)).andThen(
					path -> (StringUtils.substringBeforeLast(StringUtils.substringBeforeLast(path, "\\"), "\\"))),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PATH)).andThen(
					path -> StringUtils.substringBeforeLast(path, "\\")),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PATH)),
			new CheckedFunction<BlackboardArtifact, AttributeEventDescription>() {
		@Override
		public AttributeEventDescription apply(BlackboardArtifact artf) throws TskCoreException {
			long time = artf.getAttribute(RECENT_DOCUMENTS.getDateTimeAttributeType()).getValueLong();
			//Non-default description construction
			String shortDescription = RECENT_DOCUMENTS.getShortExtractor().apply(artf);
			String medDescription = RECENT_DOCUMENTS.getMedExtractor().apply(artf);
			String fullDescription = RECENT_DOCUMENTS.getFullExtractor().apply(artf);

			return new AttributeEventDescription(time, shortDescription, medDescription, fullDescription);
		}
	});
	public static final MiscType INSTALLED_PROGRAM = new MiscType(BUNDLE.getString("MiscTypes.installedPrograms.name"), // NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_INSTALLED_PROG),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PROG_NAME)),
			new EmptyExtractor(),
			new EmptyExtractor());
	public static final MiscType EXIF = new MiscType(BUNDLE.getString("MiscTypes.exif.name"), // NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_METADATA_EXIF),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_CREATED),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_MAKE)),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_MODEL)),
			artf -> {
				try {
					AbstractFile file = artf.getSleuthkitCase().getAbstractFileById(artf.getObjectID());
					if (file != null) {
						return file.getName();
					}
				} catch (TskCoreException ex) {
					LOGGER.log(Level.SEVERE, "Exif event type failed to look up backing file name", ex); //NON-NLS
				}
				return "error loading file name";
			});
	public static final MiscType DEVICES_ATTACHED = new MiscType(BUNDLE.getString("MiscTypes.devicesAttached.name"), // NON-NLS
			new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_DEVICE_ATTACHED),
			new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_MAKE)),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_MODEL)),
			new AttributeExtractor(new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_ID)));

	private final BlackboardArtifact.Type artifactType;
	private final BlackboardAttribute.Type dateTimeAttributeType;
	private final Function<BlackboardArtifact, String> longExtractor;
	private final Function<BlackboardArtifact, String> medExtractor;
	private final Function<BlackboardArtifact, String> shortExtractor;
	private final CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper;

	static public String stringValueOf(BlackboardAttribute attr) {
		return Optional.ofNullable(attr)
				.map(BlackboardAttribute::getDisplayString)
				.orElse("");
	}

	public static String toFrom(BlackboardAttribute dir) {
		if (dir == null) {
			return "";
		} else {
			switch (dir.getDisplayString()) {
				case "Incoming": // NON-NLS
					return "from"; // NON-NLS
				case "Outgoing": // NON-NLS
					return "to"; // NON-NLS
				default:
					return ""; // NON-NLS
			}
		}
	}

	private MiscType(String displayName, BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			Function<BlackboardArtifact, String> shortExtractor,
			Function<BlackboardArtifact, String> medExtractor,
			Function<BlackboardArtifact, String> longExtractor) {
		this(displayName, artifactType, dateTimeAttributeType, shortExtractor, medExtractor, longExtractor, null);
	}

	private MiscType(String displayName, BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			Function<BlackboardArtifact, String> shortExtractor,
			Function<BlackboardArtifact, String> medExtractor,
			Function<BlackboardArtifact, String> longExtractor,
			CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper) {
		super(displayName, EventTypeZoomLevel.SUB_TYPE, BaseType.MISC_TYPES, Collections.emptySet());
		this.artifactType = artifactType;
		this.dateTimeAttributeType = dateTimeAttributeType;
		this.shortExtractor = shortExtractor;
		this.medExtractor = medExtractor;
		this.longExtractor = longExtractor;
		this.parseAttributesHelper = parseAttributesHelper;
	}

	@Override
	public AttributeEventDescription parseAttributesHelper(BlackboardArtifact artf) throws TskCoreException {
		if (this.parseAttributesHelper == null) {
			return this.parseAttributesHelper(artf);
		} else {
			return this.parseAttributesHelper.apply(artf);
		}
	}

	@Override
	public Function<BlackboardArtifact, String> getFullExtractor() {
		return longExtractor;
	}

	@Override
	public Function<BlackboardArtifact, String> getMedExtractor() {
		return medExtractor;
	}

	@Override
	public Function<BlackboardArtifact, String> getShortExtractor() {
		return shortExtractor;
	}

	@Override
	public BlackboardAttribute.Type getDateTimeAttributeType() {
		return dateTimeAttributeType;
	}

	@Override
	public BlackboardArtifact.Type getArtifactType() {
		return artifactType;
	}

	@Override
	public int getTypeID() {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
	}

}
