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
 * This class definition mirrors the EmailMessageFacet observable described in the
 UCO ontology.
 */
class EmailMessageFacet extends Facet {

    @SerializedName("observable:receivedTime")
    private String receivedTime;

    @SerializedName("observable:sentTime")
    private String sentTime;

    @SerializedName("observable:bcc")
    private String bcc;

    @SerializedName("observable:cc")
    private String cc;

    @SerializedName("observable:from")
    private String from;

    @SerializedName("observable:headerRaw")
    private String headerRaw;

    @SerializedName("observable:MessageID")
    private String messageID;

    @SerializedName("observable:subject")
    private String subject;

    @SerializedName("observable:sender")
    private String sender;

    @SerializedName("observable:inReplyTo")
    private String inReplyTo;

    @SerializedName("observable:body")
    private String body;

    @SerializedName("observable:contentType")
    private String contentType;

    EmailMessageFacet() {
        super(EmailMessageFacet.class.getSimpleName());
    }

    EmailMessageFacet setBody(String body) {
        this.body = body;
        return this;
    }

    EmailMessageFacet setContentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    EmailMessageFacet setReceivedTime(Long receivedTime) {
        if (receivedTime != null) {
            this.receivedTime = Instant.ofEpochSecond(receivedTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    EmailMessageFacet setSentTime(Long sentTime) {
        if (sentTime != null) {
            this.sentTime = Instant.ofEpochSecond(sentTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    EmailMessageFacet setBcc(CyberItem bcc) {
        this.bcc = bcc.getId();
        return this;
    }

    EmailMessageFacet setCc(CyberItem cc) {
        this.cc = cc.getId();
        return this;
    }

    EmailMessageFacet setFrom(CyberItem from) {
        this.from = from.getId();
        return this;
    }

    EmailMessageFacet setHeaderRaw(CyberItem headerRaw) {
        this.headerRaw = headerRaw.getId();
        return this;
    }

    EmailMessageFacet setMessageID(String messageID) {
        this.messageID = messageID;
        return this;
    }

    EmailMessageFacet setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    EmailMessageFacet setSender(CyberItem sender) {
        this.sender = sender.getId();
        return this;
    }

    EmailMessageFacet setInReplyTo(CyberItem replyTo) {
        this.inReplyTo = replyTo.getId();
        return this;
    }

    String getReceivedTime() {
        return receivedTime;
    }

    String getSentTime() {
        return sentTime;
    }

    String getBcc() {
        return bcc;
    }

    String getCc() {
        return cc;
    }

    String getFrom() {
        return from;
    }

    String getHeaderRaw() {
        return headerRaw;
    }

    String getMessageID() {
        return messageID;
    }

    String getSubject() {
        return subject;
    }

    String getSender() {
        return sender;
    }

    String getInReplyTo() {
        return inReplyTo;
    }

    String getBody() {
        return body;
    }

    String getContentType() {
        return contentType;
    }
}
