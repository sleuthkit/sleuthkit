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
 * This class definition mirrors the MessageFacet observable described in the UCO
 ontology.
 */
class MessageFacet extends Facet {

    @SerializedName("observable:messageText")
    private String messageText;

    @SerializedName("observable:application")
    private String application;

    @SerializedName("observable:sentTime")
    private String sentTime;

    @SerializedName("observable:messageType")
    private String messageType;

    MessageFacet() {
        super(MessageFacet.class.getSimpleName());
    }

    MessageFacet setMessageText(String messageText) {
        this.messageText = messageText;
        return this;
    }

    MessageFacet setApplication(ObservableObject application) {
        this.application = application.getId();
        return this;
    }

    MessageFacet setSentTime(Long sentTime) {
        if (sentTime != null) {
            this.sentTime = Instant.ofEpochSecond(sentTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    MessageFacet setMessageType(String messageType) {
        this.messageType = messageType;
        return this;
    }

    @Override
    MessageFacet setId(String id) {
        super.setId("_:" + id);
        return this;
    }

    String getMessageText() {
        return messageText;
    }

    String getApplication() {
        return application;
    }

    String getSentTime() {
        return sentTime;
    }

    String getMessageType() {
        return messageType;
    }
}
