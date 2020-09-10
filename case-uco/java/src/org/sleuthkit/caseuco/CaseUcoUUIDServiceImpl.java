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
 * Default implementation for generating unique @id properties in the CASE
 * output. The default values consist of the CaseDB name and
 * the content id.
 */
class CaseUcoUUIDServiceImpl implements CaseUcoUUIDService {

    private final String databaseName;

    CaseUcoUUIDServiceImpl(SleuthkitCase sleuthkitCase) {
        this.databaseName = sleuthkitCase.getDatabaseName();
    }

    @Override
    public String createUUID(Content content) {
        return "_:content-" + content.getId() + "_" + databaseName;
    }

    @Override
    public String createUUID(ContentTag contentTag) {
        return "_:tag-" + contentTag.getId() + "_" + databaseName;
    }

    @Override
    public String createUUID(SleuthkitCase sleuthkitCase) {
        return "_:case-" + sleuthkitCase.getDatabaseName();
    }
}
