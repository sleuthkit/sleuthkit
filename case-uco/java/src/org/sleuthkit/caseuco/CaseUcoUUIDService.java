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

import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.ContentTag;

/**
 * Providing a way to customize UUIDs is a necessary feature to promote the
 * reuse of the CaseUcoExporter class. IDs in a REST API use case would prefer
 * links to the relevant endpoints and IDs in a standalone TSK application may
 * prefer a combination of object id, case id, and time stamp. A runtime object
 * that provides this service is a good way to address content objects that
 * reference other content objects. For example, when the CaesUcoExporter is
 * asked to export a TSK_ASSOCIATED_ARTIFACT_HIT or a ContentTag, it'll also
 * need to export the reference to the underlying content as well. It wouldn't
 * be very user friendly if we asked for these IDs up front, so instead it's
 * quite handy to have some service that can be set once and forgotten about
 * during execution.
 */
public interface CaseUcoUUIDService {

    public String createUUID(Content content);
    public String createUUID(ContentTag contentTag);
}
