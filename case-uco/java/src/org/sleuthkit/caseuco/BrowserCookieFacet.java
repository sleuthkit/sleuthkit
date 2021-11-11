/*
 * Sleuth Kit CASE JSON LD Support
 *
 * Copyright 2020-2021 Basis Technology Corp.
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

import com.google.gson.annotations.SerializedName;
import java.time.Instant;
import java.time.ZoneOffset;

/**
 * This class definition mirrors the BrowserCookieFacet observable described in the
 UCO ontology.
 */
class BrowserCookieFacet extends Facet {

   @SerializedName("observable:cookieName")
   private String cookieName;

   @SerializedName("observable:accessedTime")
   private String accessedTime;

   @SerializedName("observable:expirationTime")
   private String expirationTime;

   @SerializedName("observable:cookieDomain")
   private String cookieDomain;

   @SerializedName("observable:sourceApplication")
   private String application;

   @SerializedName("observable:cookiePath")
   private String cookiePath;

    BrowserCookieFacet() {
        super(BrowserCookieFacet.class.getSimpleName());
    }

    BrowserCookieFacet setCookieName(String cookieName) {
        this.cookieName = cookieName;
        return this;
    }

    BrowserCookieFacet setAccessedTime(Long accessedTime) {
        if (accessedTime != null) {
            this.accessedTime = Instant.ofEpochSecond(accessedTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    BrowserCookieFacet setExpirationTime(Long expirationTime) {
        if (expirationTime != null) {
            this.expirationTime = Instant.ofEpochSecond(expirationTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    BrowserCookieFacet setCookieDomain(CyberItem cookieDomain) {
        this.cookieDomain = cookieDomain.getId();
        return this;
    }

    BrowserCookieFacet setApplication(CyberItem application) {
        this.application = application.getId();
        return this;
    }

    BrowserCookieFacet setCookiePath(String cookiePath) {
        this.cookiePath = cookiePath;
        return this;
    }

    String getCookieName() {
        return cookieName;
    }

    String getAccessedTime() {
        return accessedTime;
    }

    String getExpirationTime() {
        return expirationTime;
    }

    String getCookieDomain() {
        return cookieDomain;
    }

    String getApplication() {
        return application;
    }

    String getCookiePath() {
        return cookiePath;
    }
}
