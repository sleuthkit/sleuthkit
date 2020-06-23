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
package org.sleuthkit.uco.observable;

import java.time.Instant;
import java.time.ZoneOffset;
import org.sleuthkit.uco.core.Facet;

public class Message extends Facet {
    
    private String messageText;
    
    private String application;
    
    public String sentTime;
    
    private String messageType;
    
    public Message() {
        super(Message.class.getSimpleName());
    }

    public Message setMessageText(String messageText) {
        this.messageText = messageText;
        return this;
    }

    public Message setApplication(CyberItem application) {
        this.application = application.getId();
        return this;
    }

    public Message setSentTime(Long sentTime) {
        if (sentTime != null) {
            this.sentTime = Instant.ofEpochSecond(sentTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    public Message setMessageType(String messageType) {
        this.messageType = messageType;
        return this;
    }
    
    @Override
    public Message setId(String id) {
        super.setId("_:" + id);
        return this;
    }
}
