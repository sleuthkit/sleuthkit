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

import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;

/**
 * Convenience class for accessing blackboard attributes using the naming scheme
 * found in the ATTRIBUTE_TYPE enum.
 */
class StandardAttributeTypes {

    static final BlackboardAttribute.Type TSK_NAME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_NAME);
    static final BlackboardAttribute.Type TSK_DATETIME_CREATED = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_CREATED);
    static final BlackboardAttribute.Type TSK_PROG_NAME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PROG_NAME);
    static final BlackboardAttribute.Type TSK_DOMAIN = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DOMAIN);
    static final BlackboardAttribute.Type TSK_URL = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_URL);
    static final BlackboardAttribute.Type TSK_USER_NAME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_USER_NAME);
    static final BlackboardAttribute.Type TSK_DATETIME_ACCESSED = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED);
    static final BlackboardAttribute.Type TSK_DATETIME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME);
    static final BlackboardAttribute.Type TSK_VALUE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_VALUE);
    static final BlackboardAttribute.Type TSK_PATH = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PATH);
    static final BlackboardAttribute.Type TSK_PATH_SOURCE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PATH_SOURCE);
    static final BlackboardAttribute.Type TSK_COMMENT = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_COMMENT);
    static final BlackboardAttribute.Type TSK_SET_NAME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_SET_NAME);
    static final BlackboardAttribute.Type TSK_DEVICE_MAKE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_MAKE);
    static final BlackboardAttribute.Type TSK_DEVICE_MODEL = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_MODEL);
    static final BlackboardAttribute.Type TSK_DEVICE_ID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_ID);
    static final BlackboardAttribute.Type TSK_MAC_ADDRESS = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_MAC_ADDRESS);
    static final BlackboardAttribute.Type TSK_PATH_ID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PATH_ID);
    static final BlackboardAttribute.Type TSK_DATETIME_START = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_START);
    static final BlackboardAttribute.Type TSK_DATETIME_END = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_END);
    static final BlackboardAttribute.Type TSK_HASH_PHOTODNA = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_HASH_PHOTODNA);
    static final BlackboardAttribute.Type TSK_EMAIL_CONTENT_HTML = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_HTML);
    static final BlackboardAttribute.Type TSK_EMAIL_CONTENT_PLAIN = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_PLAIN);
    static final BlackboardAttribute.Type TSK_EMAIL_CONTENT_RTF = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_CONTENT_RTF);
    static final BlackboardAttribute.Type TSK_DATETIME_RCVD = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_RCVD);
    static final BlackboardAttribute.Type TSK_DATETIME_SENT = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_SENT);
    static final BlackboardAttribute.Type TSK_EMAIL_BCC = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_BCC);
    static final BlackboardAttribute.Type TSK_EMAIL_CC = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_CC);
    static final BlackboardAttribute.Type TSK_EMAIL_FROM = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_FROM);
    static final BlackboardAttribute.Type TSK_EMAIL_TO = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_TO);
    static final BlackboardAttribute.Type TSK_HEADERS = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_HEADERS);
    static final BlackboardAttribute.Type TSK_MSG_ID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_MSG_ID);
    static final BlackboardAttribute.Type TSK_SUBJECT = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_SUBJECT);
    static final BlackboardAttribute.Type TSK_TEXT = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_TEXT);
    static final BlackboardAttribute.Type TSK_VERSION = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_VERSION);
    static final BlackboardAttribute.Type TSK_PRODUCT_ID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PRODUCT_ID);
    static final BlackboardAttribute.Type TSK_PROCESSOR_ARCHITECTURE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PROCESSOR_ARCHITECTURE);
    static final BlackboardAttribute.Type TSK_ORGANIZATION = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ORGANIZATION);
    static final BlackboardAttribute.Type TSK_OWNER = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_OWNER);
    static final BlackboardAttribute.Type TSK_TEMP_DIR = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_TEMP_DIR);
    static final BlackboardAttribute.Type TSK_GEO_ALTITUDE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_ALTITUDE);
    static final BlackboardAttribute.Type TSK_GEO_LATITUDE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_LATITUDE);
    static final BlackboardAttribute.Type TSK_GEO_LONGITUDE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE);
    static final BlackboardAttribute.Type TSK_EMAIL = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL);
    static final BlackboardAttribute.Type TSK_PHONE_NUMBER = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER);
    static final BlackboardAttribute.Type TSK_PHONE_NUMBER_TO = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO);
    static final BlackboardAttribute.Type TSK_PHONE_NUMBER_FROM = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM);
    static final BlackboardAttribute.Type TSK_PHONE_NUMBER_HOME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_HOME);
    static final BlackboardAttribute.Type TSK_PHONE_NUMBER_MOBILE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_MOBILE);
    static final BlackboardAttribute.Type TSK_PHONE_NUMBER_OFFICE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_OFFICE);
    static final BlackboardAttribute.Type TSK_EMAIL_HOME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_HOME);
    static final BlackboardAttribute.Type TSK_EMAIL_OFFICE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_OFFICE);
    static final BlackboardAttribute.Type TSK_MESSAGE_TYPE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE);
    static final BlackboardAttribute.Type TSK_DIRECTION = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DIRECTION);
    static final BlackboardAttribute.Type TSK_READ_STATUS = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_READ_STATUS);
    static final BlackboardAttribute.Type TSK_THREAD_ID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_THREAD_ID);
    static final BlackboardAttribute.Type TSK_CATEGORY = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_CATEGORY);
    static final BlackboardAttribute.Type TSK_EMAIL_REPLYTO = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_EMAIL_REPLYTO);
    static final BlackboardAttribute.Type TSK_PASSWORD = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_PASSWORD);
    static final BlackboardAttribute.Type TSK_USER_ID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_USER_ID);
    static final BlackboardAttribute.Type TSK_ACCOUNT_TYPE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ACCOUNT_TYPE);
    static final BlackboardAttribute.Type TSK_DISPLAY_NAME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DISPLAY_NAME);
    static final BlackboardAttribute.Type TSK_DESCRIPTION = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DESCRIPTION);
    static final BlackboardAttribute.Type TSK_GROUPS = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GROUPS);
    static final BlackboardAttribute.Type TSK_ATTACHMENTS = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ATTACHMENTS);
    static final BlackboardAttribute.Type TSK_FLAG = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_FLAG);
    static final BlackboardAttribute.Type TSK_COUNT = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_COUNT);
    static final BlackboardAttribute.Type TSK_LOCATION = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_LOCATION);
    static final BlackboardAttribute.Type TSK_DEVICE_NAME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DEVICE_NAME);
    static final BlackboardAttribute.Type TSK_CALENDAR_ENTRY_TYPE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_CALENDAR_ENTRY_TYPE);
    static final BlackboardAttribute.Type TSK_NAME_PERSON = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_NAME_PERSON);
    static final BlackboardAttribute.Type TSK_REMOTE_PATH = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_REMOTE_PATH);
    static final BlackboardAttribute.Type TSK_LOCAL_PATH = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_LOCAL_PATH);
    static final BlackboardAttribute.Type TSK_SSID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_SSID);
    static final BlackboardAttribute.Type TSK_IMEI = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_IMEI);
    static final BlackboardAttribute.Type TSK_ICCID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ICCID);
    static final BlackboardAttribute.Type TSK_IMSI = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_IMSI);
    static final BlackboardAttribute.Type TSK_ID = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ID);
    static final BlackboardAttribute.Type TSK_CARD_NUMBER = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_CARD_NUMBER);
    static final BlackboardAttribute.Type TSK_ASSOCIATED_ARTIFACT = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_ASSOCIATED_ARTIFACT);
    static final BlackboardAttribute.Type TSK_DATETIME_MODIFIED = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED);
    static final BlackboardAttribute.Type TSK_GEO_TRACKPOINTS = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_GEO_TRACKPOINTS);
    static final BlackboardAttribute.Type TSK_TL_EVENT_TYPE = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_TL_EVENT_TYPE);
    static final BlackboardAttribute.Type TSK_LAST_PRINTED_DATETIME = new BlackboardAttribute.Type(ATTRIBUTE_TYPE.TSK_LAST_PRINTED_DATETIME);
}