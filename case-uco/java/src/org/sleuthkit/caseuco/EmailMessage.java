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
 * This class definition mirrors the EmailMessage observable described in the
 * UCO ontology.
 */
class EmailMessage extends Facet {

    private String receivedTime;

    private String sentTime;

    private String bcc;

    private String cc;

    private String from;

    private String headerRaw;

    private String messageID;

    private String subject;

    private String sender;

    private String inReplyTo;

    private String body;

    private String contentType;

    EmailMessage() {
        super(EmailMessage.class.getSimpleName());
    }

    EmailMessage setBody(String body) {
        this.body = body;
        return this;
    }

    EmailMessage setContentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    EmailMessage setReceivedTime(Long receivedTime) {
        if (receivedTime != null) {
            this.receivedTime = Instant.ofEpochSecond(receivedTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    EmailMessage setSentTime(Long sentTime) {
        if (sentTime != null) {
            this.sentTime = Instant.ofEpochSecond(sentTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    EmailMessage setBcc(CyberItem bcc) {
        this.bcc = bcc.getId();
        return this;
    }

    EmailMessage setCc(CyberItem cc) {
        this.cc = cc.getId();
        return this;
    }

    EmailMessage setFrom(CyberItem from) {
        this.from = from.getId();
        return this;
    }

    EmailMessage setHeaderRaw(CyberItem headerRaw) {
        this.headerRaw = headerRaw.getId();
        return this;
    }

    EmailMessage setMessageID(String messageID) {
        this.messageID = messageID;
        return this;
    }

    EmailMessage setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    EmailMessage setSender(CyberItem sender) {
        this.sender = sender.getId();
        return this;
    }

    EmailMessage setInReplyTo(CyberItem replyTo) {
        this.inReplyTo = replyTo.getId();
        return this;
    }
}
