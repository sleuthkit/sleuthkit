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

import com.google.common.collect.ImmutableSortedSet;
import com.google.common.net.InternetDomainName;
import java.util.ResourceBundle;
import java.util.function.Function;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.BlackboardArtifact;
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.*;
import org.sleuthkit.datamodel.BlackboardAttribute;
import static org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE.*;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.timeline.eventtype.AbstractArtifactEventType.AttributeExtractor;
import org.sleuthkit.datamodel.timeline.eventtype.ArtifactEventType.AttributeEventDescription;

/**
 *
 */
public final class WebType extends AbstractArtifactEventType {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.eventtype.Bundle");  // NON-NLS

	public final static WebType WEB_DOWNLOADS = new WebType(8, BUNDLE.getString("WebTypes.webDownloads.name"),
			new BlackboardArtifact.Type(TSK_WEB_DOWNLOAD),
			new BlackboardAttribute.Type(TSK_DATETIME_ACCESSED),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_PATH)),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_URL)),
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
	public final static WebType WEB_COOKIE = new WebType(9, BUNDLE.getString("WebTypes.webCookies.name"),
			new BlackboardArtifact.Type(TSK_WEB_COOKIE),
			new BlackboardAttribute.Type(TSK_DATETIME),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_NAME)),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_VALUE)));
	public final static WebType WEB_BOOKMARK = new WebType(10, BUNDLE.getString("WebTypes.webBookmarks.name"),
			new BlackboardArtifact.Type(TSK_WEB_BOOKMARK),
			new BlackboardAttribute.Type(TSK_DATETIME_CREATED),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_URL)),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_TITLE)));
	public final static WebType WEB_HISTORY = new WebType(11, BUNDLE.getString("WebTypes.webHistory.name"),
			new BlackboardArtifact.Type(TSK_WEB_HISTORY),
			new BlackboardAttribute.Type(TSK_DATETIME_ACCESSED),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_URL)),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_TITLE)));
	public final static WebType WEB_SEARCH = new WebType(12, BUNDLE.getString("WebTypes.webSearch.name"),
			new BlackboardArtifact.Type(TSK_WEB_SEARCH_QUERY),
			new BlackboardAttribute.Type(TSK_DATETIME_ACCESSED),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_TEXT)),
			TopPrivateDomainExtractor.getInstance(),
			new AttributeExtractor(new BlackboardAttribute.Type(TSK_PROG_NAME)));

	@SuppressWarnings("deprecation")
	private static final ImmutableSortedSet<? extends WebType> VALUES
			= ImmutableSortedSet.of(WEB_DOWNLOADS, WEB_COOKIE, WEB_BOOKMARK, WEB_HISTORY, WEB_SEARCH);

public	static ImmutableSortedSet<? extends WebType> values() {
		return VALUES;
	}

	private WebType(int id,
			String displayName,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			Function<BlackboardArtifact, String> shortExtractor,
			Function<BlackboardArtifact, String> medExtractor,
			Function<BlackboardArtifact, String> longExtractor) {
		this(id, displayName, artifactType, dateTimeAttributeType, shortExtractor, medExtractor, longExtractor, null);
	}

	private WebType(
			int id,
			String displayName,
			BlackboardArtifact.Type artifactType,
			BlackboardAttribute.Type dateTimeAttributeType,
			Function<BlackboardArtifact, String> shortExtractor,
			Function<BlackboardArtifact, String> medExtractor,
			Function<BlackboardArtifact, String> longExtractor,
			AbstractArtifactEventType.CheckedFunction<BlackboardArtifact, AttributeEventDescription> parseAttributesHelper) {
		super(id, displayName, BaseType.WEB_ACTIVITY, artifactType,
				dateTimeAttributeType, shortExtractor, medExtractor,
				longExtractor, parseAttributesHelper);
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
			super(new BlackboardAttribute.Type(TSK_DOMAIN));
		}
	}
}
