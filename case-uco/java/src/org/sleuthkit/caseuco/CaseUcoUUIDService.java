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
import org.sleuthkit.datamodel.SleuthkitCase;

/**
 * Providing a way to customize UUIDs is a necessary feature to promote the
 * reuse of the CaseUcoExporter class. For example, REST API IDs would prefer
 * links to the relevant endpoints and IDs in a standalone TSK application may
 * prefer a combination of object id, case name, and time stamp. A runtime
 * object that provides this service is a nice 'hands-off' approach to exporting
 * content that references other content objects. For example,
 * TSK_ASSOCIATED_ARTIFACT_HIT and ContentTag both reference other content
 * instances that need to be linked in the CASE output. Creating a class for
 * this task guarantees consistent IDs and ensures the API is simple to use.
 *
 * CaseUcoExporter already ships with a default implementation of this class.
 * The default implementation will use the object id and database name. To
 * override the default, please refer to the CaseUcoExporter documentation.
 */
public interface CaseUcoUUIDService {

    public String createUUID(Content content);

    public String createUUID(ContentTag contentTag);

    public String createUUID(SleuthkitCase sleuthkitCase);
}
