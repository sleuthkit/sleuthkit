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

/**
 * This class definition mirrors the BrowserBookmark observable described in the
 * UCO ontology.
 */
class BrowserBookmark extends Facet {

    private String urlTargeted;

    private String application;

    BrowserBookmark() {
        super(BrowserBookmark.class.getSimpleName());
    }

    BrowserBookmark setUrlTargeted(String urlTargeted) {
        this.urlTargeted = urlTargeted;
        return this;
    }

    BrowserBookmark setApplication(CyberItem application) {
        this.application = application.getId();
        return this;
    }
}
