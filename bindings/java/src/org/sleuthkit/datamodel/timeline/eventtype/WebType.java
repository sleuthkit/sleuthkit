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

import com.google.common.collect.ImmutableList;
import com.google.common.net.InternetDomainName;
import java.util.Collections;
import java.util.ResourceBundle;
import java.util.function.Function;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;
import org.sleuthkit.datamodel.timeline.eventtype.ArtifactEventType.AttributeEventDescription;
import org.sleuthkit.datamodel.timeline.eventtype.ArtifactEventType.AttributeExtractor;
import static org.sleuthkit.datamodel.timeline.eventtype.FileSystemType.FILE_ACCESSED;
import static org.sleuthkit.datamodel.timeline.eventtype.FileSystemType.FILE_CHANGED;
import static org.sleuthkit.datamodel.timeline.eventtype.FileSystemType.FILE_CREATED;
import static org.sleuthkit.datamodel.timeline.eventtype.FileSystemType.FILE_MODIFIED;

/**
 *
 */
public final class WebType extends AbstractEventType implements ArtifactEventType {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.eventtype.Bundle");  // NON-NLS

	public final static WebType WEB_DOWNLOADS = new WebType(BUNDLE.getString("WebTypes.webDownloads.name"),
			new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD),
			new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH)),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL)),
			new CheckedFunction<BlackboardArtifact, AttributeEventDescription>() {
		@Override
		public AttributeEventDescription apply(BlackboardArtifact artf) throws TskCoreException {
			long time = artf.getAttribute(WEB_DOWNLOADS.getDateTimeAttributeType()).getValueLong();
			String domain = WEB_DOWNLOADS.getShortExtractor().apply(artf);
			String path = WEB_DOWNLOADS.getMedExtractor().apply(artf);
			String fileName = StringUtils.substringAfterLast(path, "/");
			String url = WEB_DOWNLOADS.getFullExtractor().apply(artf);

			//TODO: review non default description construction
			String shortDescription = fileName + " from " + domain; // NON-NLS
			String medDescription = fileName + " from " + url; // NON-NLS
			String fullDescription = path + " from " + url; // NON-NLS
			return new AttributeEventDescription(time, shortDescription, medDescription, fullDescription);
		}
	});
	public final static WebType WEB_COOKIE = new WebType(BUNDLE.getString("WebTypes.webCookies.name"),
			new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE),
			new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME)),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE)));
	public final static WebType WEB_BOOKMARK = new WebType(BUNDLE.getString("WebTypes.webBookmarks.name"),
			new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_BOOKMARK),
			new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL)),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE)));
	public final static WebType WEB_HISTORY = new WebType(BUNDLE.getString("WebTypes.webHistory.name"),
			new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY),
			new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL)),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE)));
	public final static WebType WEB_SEARCH = new WebType(BUNDLE.getString("WebTypes.webSearch.name"),
			new BlackboardArtifact.Type(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_SEARCH_QUERY),
			new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT)),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME)));

	private static final ImmutableList<WebType> VALUES
			= ImmutableList.of(WEB_DOWNLOADS, WEB_COOKIE, WEB_BOOKMARK, WEB_HISTORY, WEB_SEARCH);

	static ImmutableList<WebType> values() {
		return VALUES;
	}

	private final BlackboardArtifact.Type artifactType;
	private final BlackboardAttribute.Type dateTimeAttributeType;
	private final Function<BlackboardArtifact, String> longExtractor;
	private final Function<BlackboardArtifact, String> medExtractor;
	private final Function<BlackboardArtifact, String> shortExtractor;
	private final CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper;

	@Override
	public BlackboardAttribute.Type getDateTimeAttributeType() {
		return dateTimeAttributeType;
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
	public BlackboardArtifact.Type getArtifactType() {
		return artifactType;
	}

	private WebType(String displayName, BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			Function<BlackboardArtifact, String> shortExtractor,
			Function<BlackboardArtifact, String> medExtractor,
			Function<BlackboardArtifact, String> longExtractor) {
		this(displayName, artifactType, dateTimeAttributeType, shortExtractor, medExtractor, longExtractor, null);
	}

	private WebType(String displayName, BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			Function<BlackboardArtifact, String> shortExtractor,
			Function<BlackboardArtifact, String> medExtractor,
			Function<BlackboardArtifact, String> longExtractor,
			CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper) {

		super(displayName, EventTypeZoomLevel.SUB_TYPE, BaseType.WEB_ACTIVITY, Collections.emptySet());
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
	public int getTypeID() {
		throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.

	}

	private static class TopPrivateDomainExtractor extends AttributeExtractor {

		final private static TopPrivateDomainExtractor instance = new TopPrivateDomainExtractor();

		static TopPrivateDomainExtractor getInstance() {
			return instance;
		}

		@Override
		public String apply(BlackboardArtifact artf) {
			String domainString = StringUtils.substringBefore(super.apply(artf), "/");
			if (InternetDomainName.isValid(domainString)) {
				InternetDomainName domain = InternetDomainName.from(domainString);
				return (domain.isUnderPublicSuffix())
						? domain.topPrivateDomain().toString()
						: domain.toString();
			} else {
				return domainString;
			}
		}

		TopPrivateDomainExtractor() {
			super(new BlackboardAttribute.Type(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN));
		}
	}

}
