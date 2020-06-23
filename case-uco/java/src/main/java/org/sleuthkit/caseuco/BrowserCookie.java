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

import java.time.Instant;
import java.time.ZoneOffset;

/**
 * This class definition mirrors the BrowserCookie observable described in the
 * UCO ontology.
 */
class BrowserCookie extends Facet {

    private String cookieName;

    private String accessedTime;

    private String expirationTime;

    private String cookieDomain;

    private String application;

    private String cookiePath;

    BrowserCookie() {
        super(BrowserCookie.class.getSimpleName());
    }

    BrowserCookie setCookieName(String cookieName) {
        this.cookieName = cookieName;
        return this;
    }

    BrowserCookie setAccessedTime(Long accessedTime) {
        if (accessedTime != null) {
            this.accessedTime = Instant.ofEpochSecond(accessedTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    BrowserCookie setExpirationTime(Long expirationTime) {
        if (expirationTime != null) {
            this.expirationTime = Instant.ofEpochSecond(expirationTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    BrowserCookie setCookieDomain(CyberItem cookieDomain) {
        this.cookieDomain = cookieDomain.getId();
        return this;
    }

    BrowserCookie setApplication(CyberItem application) {
        this.application = application.getId();
        return this;
    }

    BrowserCookie setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
        return this;
    }
}
