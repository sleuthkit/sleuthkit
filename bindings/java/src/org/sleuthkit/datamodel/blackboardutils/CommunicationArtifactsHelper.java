/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel.blackboardutils;

import com.google.gson.Gson;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Account;
import org.sleuthkit.datamodel.AccountFileInstance;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.DataSource;
import org.sleuthkit.datamodel.Relationship;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskDataException;

/**
 * Class to help ingest modules create communication artifacts. Communication
 * artifacts includes contacts, messages, call logs.
 *
 * It creates a 'self' account {@link Account} - an account for the owner/user
 * of the application being processed by the module. As an example, for a module
 * analyzing Facebook application, this would be account associated with the
 * unique Facebook user id of the device owner.
 *
 * In the absence of a 'self' account, a 'device' account may be used in it's
 * place. A 'device' account is an account meant to represent the owner of the
 * device and uses the unique device id as the unique account identifier.
 *
 * It also creates accounts for contacts, and sender/receivers of the messages,
 * and calls.
 *
 * And it also creates relationships between the self account - and the contacts
 * and sender/receiver accounts.
 *
 */
public final class CommunicationArtifactsHelper extends ArtifactHelperBase {

	/**
	 * Enum for message read status
	 */
	public enum MessageReadStatus {

		UNKNOWN("Unknown"), /// read status is unknown
		UNREAD("Unread"), /// message has not been read
		READ("Read");     /// message has been read

		private final String msgReadStr;

		MessageReadStatus(String readStatus) {
			this.msgReadStr = readStatus;
		}

		public String getDisplayName() {
			return msgReadStr;
		}
	}

	/**
	 * Enum for call/message direction.
	 */
	public enum CommunicationDirection {
		UNKNOWN("Unknown"),
		INCOMING("Incoming"),
		OUTGOING("Outgoing");

		private final String dirStr;

		CommunicationDirection(String dir) {
			this.dirStr = dir;
		}

		public String getDisplayName() {
			return dirStr;
		}
	}

	/**
	 * Enum for call media type.
	 */
	public enum CallMediaType {
		UNKNOWN("Unknown"),
		AUDIO("Audio"), // Audio only call
		VIDEO("Video");	// Video/multimedia call

		private final String typeStr;

		CallMediaType(String type) {
			this.typeStr = type;
		}

		public String getDisplayName() {
			return typeStr;
		}
	}

	// 'self' account for the application being processed by the module. 
	private final Account.Type selfAccountType;
	private final String selfAccountId;
			
	private AccountFileInstance selfAccountInstance = null;

	// Type of accounts to be created for the module using this helper.
	private final Account.Type moduleAccountsType;

	/**
	 * Constructs a communications artifacts helper for the given source file.
	 *
	 * This is a constructor for modules that do not have a 'self' account, and
	 * will use a 'Device' account in lieu.
	 *
	 * It creates a DeviceAccount instance to use as a self account.
	 *
	 * @param caseDb       Sleuthkit case db.
	 * @param moduleName   Name of module using the helper.
	 * @param srcContent   Source content being processed by the module.
	 * @param accountsType Account type {@link Account.Type} created by this
	 *                     module.
	 *
	 * @throws TskCoreException If there is an error creating the device
	 *                          account.
	 */
	public CommunicationArtifactsHelper(SleuthkitCase caseDb,
			String moduleName, Content srcContent, Account.Type accountsType) throws TskCoreException {

		super(caseDb, moduleName, srcContent);

		this.moduleAccountsType = accountsType;
		this.selfAccountType = Account.Type.DEVICE;
		this.selfAccountId = ((DataSource) getContent().getDataSource()).getDeviceId();
	}

	/**
	 * Constructs a AppDB parser helper for the given DB file.
	 *
	 * This constructor is for modules that have the application specific
	 * account information for the device owner to create a 'self' account.
	 *
	 * It creates an account instance with specified type & id, and uses it as
	 * the self account.
	 *
	 * @param caseDb          Sleuthkit case db.
	 * @param moduleName      Name of module using the helper.
	 * @param srcContent      Source content being processed by the module.
	 * @param accountsType    Account type {@link Account.Type} created by this
	 *                        module.
	 * @param selfAccountType Self account type to be created for this module.
	 * @param selfAccountId	  Account unique id for the self account.
	 *
	 * @throws TskCoreException	If there is an error creating the self account
	 */
	public CommunicationArtifactsHelper(SleuthkitCase caseDb, String moduleName, Content srcContent, Account.Type accountsType, Account.Type selfAccountType, String selfAccountId) throws TskCoreException {

		super(caseDb, moduleName, srcContent);

		this.moduleAccountsType = accountsType;
		this.selfAccountType = selfAccountType;
		this.selfAccountId = selfAccountId;
	}

	/**
	 * Creates and adds a TSK_CONTACT artifact to the case, with specified
	 * attributes. Also creates an account instance of specified type for the
	 * contact with the specified ID.
	 *
	 * @param contactName       Contact name, required.
	 * @param phoneNumber       Primary phone number for contact, may be empty
	 *                          or null.
	 * @param homePhoneNumber   Home phone number, may be empty or null.
	 * @param mobilePhoneNumber Mobile phone number, may be empty or null.
	 * @param emailAddr         Email address for the contact, may be empty or
	 *                          null.
	 *
	 * At least one phone number or email address is required.
	 *
	 * @return Contact artifact created.
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 *
	 */
	public BlackboardArtifact addContact(String contactName,
			String phoneNumber, String homePhoneNumber,
			String mobilePhoneNumber, String emailAddr) throws TskCoreException, BlackboardException {
		return addContact(contactName, phoneNumber,
				homePhoneNumber, mobilePhoneNumber, emailAddr,
				Collections.emptyList());
	}

	/**
	 * Creates and adds a TSK_CONTACT artifact to the case, with specified
	 * attributes. Also creates an account instance for the contact with the
	 * specified ID.
	 *
	 * @param contactName          Contact name, required
	 * @param phoneNumber          Primary phone number for contact, may be
	 *                             empty or null.
	 * @param homePhoneNumber      Home phone number, may be empty or null.
	 * @param mobilePhoneNumber    Mobile phone number, may be empty or null.
	 * @param emailAddr            Email address for the contact, may be empty
	 *                             or null.
	 *
	 * At least one phone number or email address or an Id is required. An Id
	 * may be passed in as a TSK_ID attribute in additionalAttributes.
	 *
	 * @param additionalAttributes Additional attributes for contact, may be an
	 *                             empty list.
	 *
	 * @return contact artifact created.
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 *
	 */
	public BlackboardArtifact addContact(String contactName,
			String phoneNumber, String homePhoneNumber,
			String mobilePhoneNumber, String emailAddr,
			Collection<BlackboardAttribute> additionalAttributes) throws TskCoreException, BlackboardException {

		// Contact name must be provided
		if (StringUtils.isEmpty(contactName)) {
			throw new IllegalArgumentException("Contact name must be specified.");
		}

		// check if the caller has included any phone/email/id in addtional attributes
		boolean hasAnyIdAttribute = false;
		if (additionalAttributes != null) {
			for (BlackboardAttribute attr : additionalAttributes) {
				if ((attr.getAttributeType().getTypeName().startsWith("TSK_PHONE"))
						|| (attr.getAttributeType().getTypeName().startsWith("TSK_EMAIL"))
						|| (attr.getAttributeType().getTypeName().startsWith("TSK_ID"))) {
					hasAnyIdAttribute = true;
					break;
				}
			}
		}

		// At least one phone number or email address 
		// or an optional attribute with phone/email/id must be provided
		if (StringUtils.isEmpty(phoneNumber) && StringUtils.isEmpty(homePhoneNumber)
				&& StringUtils.isEmpty(mobilePhoneNumber) && StringUtils.isEmpty(emailAddr)
				&& (!hasAnyIdAttribute)) {
			throw new IllegalArgumentException("At least one phone number or email address or an id must be provided.");
		}

		BlackboardArtifact contactArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create TSK_CONTACT artifact
		contactArtifact = getContent().newArtifact(ARTIFACT_TYPE.TSK_CONTACT);

		// construct attributes
		attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), contactName));

		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, phoneNumber, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_HOME, homePhoneNumber, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_MOBILE, mobilePhoneNumber, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_EMAIL, emailAddr, attributes);

		// add attributes
		attributes.addAll(additionalAttributes);
		contactArtifact.addAttributes(attributes);

		// create an account for each specified contact method, and a relationship with self account
		createContactMethodAccountAndRelationship(Account.Type.PHONE, phoneNumber, contactArtifact, 0);
		createContactMethodAccountAndRelationship(Account.Type.PHONE, homePhoneNumber, contactArtifact, 0);
		createContactMethodAccountAndRelationship(Account.Type.PHONE, mobilePhoneNumber, contactArtifact, 0);
		createContactMethodAccountAndRelationship(Account.Type.EMAIL, emailAddr, contactArtifact, 0);

		// if the additional attribute list has any phone/email/id attributes, create accounts & relationships for those. 
		if ((additionalAttributes != null) && hasAnyIdAttribute) {
			for (BlackboardAttribute bba : additionalAttributes) {
				if (bba.getAttributeType().getTypeName().startsWith("TSK_PHONE")) {
					createContactMethodAccountAndRelationship(Account.Type.PHONE, bba.getValueString(), contactArtifact, 0);
				} else if (bba.getAttributeType().getTypeName().startsWith("TSK_EMAIL")) {
					createContactMethodAccountAndRelationship(Account.Type.EMAIL, bba.getValueString(), contactArtifact, 0);
				} else if (bba.getAttributeType().getTypeName().startsWith("TSK_ID")) {
					createContactMethodAccountAndRelationship(this.moduleAccountsType, bba.getValueString(), contactArtifact, 0);
				}
			}
		}

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(contactArtifact, getModuleName());

		return contactArtifact;
	}

	/**
	 * Creates a contact's account instance of specified account type, if the
	 * account id is not null/empty.
	 *
	 * Also creates a CONTACT relationship between the self account and the new
	 * contact account.
	 */
	private void createContactMethodAccountAndRelationship(Account.Type accountType,
			String accountUniqueID, BlackboardArtifact sourceArtifact,
			long dateTime) throws TskCoreException {

		// Find/Create an account instance for each of the contact method
		// Create a relationship between selfAccount and contactAccount
		if (!StringUtils.isEmpty(accountUniqueID)) {
			AccountFileInstance contactAccountInstance = createAccountInstance(accountType, accountUniqueID);

			// Create a relationship between self account and the contact account
			try {
				getSleuthkitCase().getCommunicationsManager().addRelationships(getSelfAccountInstance(),
						Collections.singletonList(contactAccountInstance), sourceArtifact, Relationship.Type.CONTACT, dateTime);
			} catch (TskDataException ex) {
				throw new TskCoreException(String.format("Failed to create relationship between account = %s and account = %s.",
						getSelfAccountInstance().getAccount(), contactAccountInstance.getAccount()), ex);
			}
		}
	}

	/**
	 * Creates an account file instance{@link AccountFileInstance} associated
	 * with the DB file.
	 *
	 * @param accountType     Type of account to create.
	 * @param accountUniqueID Unique id for the account.
	 *
	 * @return Account instance created.
	 *
	 * @throws TskCoreException If there is an error creating the account
	 *                          instance.
	 */
	private AccountFileInstance createAccountInstance(Account.Type accountType, String accountUniqueID) throws TskCoreException {
		return getSleuthkitCase().getCommunicationsManager().createAccountFileInstance(accountType, accountUniqueID, getModuleName(), getContent());
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates an account instance for the sender/receiver, and creates a
	 * relationship between the self account and the sender/receiver account.
	 *
	 * @param messageType Message type, required.
	 * @param direction   Message direction, UNKNOWN if not available.
	 * @param senderId    Sender address id, may be null.
	 * @param recipientId Recipient id, may be null.
	 * @param dateTime    Date/time of message, 0 if not available.
	 * @param readStatus  Message read status, UNKNOWN if not available.
	 * @param subject     Message subject, may be empty or null.
	 * @param messageText Message body, may be empty or null.
	 * @param threadId    Message thread id, may be empty or null.
	 *
	 * @return Message artifact.
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addMessage(
			String messageType,
			CommunicationDirection direction,
			String senderId,
			String recipientId,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText, String threadId) throws TskCoreException, BlackboardException {
		return addMessage(messageType, direction,
				senderId, recipientId, dateTime, readStatus,
				subject, messageText, threadId,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates an account instance for the sender/receiver, and creates a
	 * relationship between the self account and the sender/receiver account.
	 *
	 * @param messageType         Message type, required.
	 * @param direction           Message direction, UNKNOWN if not available.
	 * @param senderId            Sender id, may be null.
	 * @param recipientId         Recipient id, may be null.
	 * @param dateTime            Date/time of message, 0 if not available.
	 * @param readStatus          Message read status, UNKNOWN if not available.
	 * @param subject             Message subject, may be empty or null.
	 * @param messageText         Message body, may be empty or null.
	 * @param threadId            Message thread id, may be empty or null.
	 * @param otherAttributesList Additional attributes, may be an empty list.
	 *
	 * @return Message artifact.
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addMessage(String messageType,
			CommunicationDirection direction,
			String senderId,
			String recipientId,
			long dateTime, MessageReadStatus readStatus, String subject,
			String messageText, String threadId,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		return addMessage(messageType, direction,
				senderId,
				Arrays.asList(recipientId),
				dateTime, readStatus,
				subject, messageText, threadId,
				otherAttributesList);
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates an account instance for the sender/receiver, and creates a
	 * relationship between the self account and the sender/receiver accounts.
	 *
	 *
	 * @param messageType      Message type, required.
	 * @param direction        Message direction, UNKNOWN if not available.
	 * @param senderId         Sender id, may be null.
	 * @param recipientIdsList Recipient ids list, may be null or empty list.
	 * @param dateTime         Date/time of message, 0 if not available.
	 * @param readStatus       Message read status, UNKNOWN if not available.
	 * @param subject          Message subject, may be empty or null.
	 * @param messageText      Message body, may be empty or null.
	 * @param threadId         Message thread id, may be empty or null.
	 *
	 * @return Message artifact.
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addMessage(String messageType,
			CommunicationDirection direction,
			String senderId,
			List<String> recipientIdsList,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText, String threadId) throws TskCoreException, BlackboardException {
		return addMessage(messageType, direction,
				senderId, recipientIdsList,
				dateTime, readStatus,
				subject, messageText, threadId,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates accounts for the sender/receivers, and creates relationships
	 * between the sender/receivers account.
	 *
	 * @param messageType         Message type, required.
	 * @param direction           Message direction, UNKNOWN if not available.
	 * @param senderId            Sender id, may be null.
	 * @param recipientIdsList    Recipient list, may be null or empty an list.
	 * @param dateTime            Date/time of message, 0 if not available.
	 * @param readStatus          Message read status, UNKNOWN if not available.
	 * @param subject             Message subject, may be empty or null.
	 * @param messageText         Message body, may be empty or null.
	 * @param threadId            Message thread id, may be empty or null.
	 * @param otherAttributesList Other attributes, may be an empty list.
	 *
	 * @return Message artifact.
	 *
	 * @throws TskCoreException    If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addMessage(String messageType,
			CommunicationDirection direction,
			String senderId,
			List<String> recipientIdsList,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText,
			String threadId,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		// Created message artifact.  
		BlackboardArtifact msgArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create TSK_MESSAGE artifact
		msgArtifact = getContent().newArtifact(ARTIFACT_TYPE.TSK_MESSAGE);

		// construct attributes
		attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE, getModuleName(), messageType));
		addAttributeIfNotZero(ATTRIBUTE_TYPE.TSK_DATETIME, dateTime, attributes);

		addMessageReadStatusIfKnown(readStatus, attributes);
		addCommDirectionIfKnown(direction, attributes);

		// set sender attribute and create sender account
		AccountFileInstance senderAccountInstance;
		if (StringUtils.isEmpty(senderId)) {
			senderAccountInstance = getSelfAccountInstance();
			addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, getSelfAccountInstance().getAccount().getTypeSpecificID(), attributes);
		} else {
			senderAccountInstance = createAccountInstance(moduleAccountsType, senderId);
			addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, senderId, attributes);
		}

		// set recipient attribute and create recipient accounts
		List<AccountFileInstance> recipientAccountsList = new ArrayList<>();
		String recipientsStr = "";
		if (recipientIdsList != null) {
			for (String recipient : recipientIdsList) {
				if (!StringUtils.isEmpty(recipient)) {
					recipientAccountsList.add(createAccountInstance(moduleAccountsType, recipient));
				}
			}
			// Create a comma separated string of recipients
			recipientsStr = addressListToString(recipientIdsList);
			addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, recipientsStr, attributes);
		}

		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_SUBJECT, subject, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_TEXT, messageText, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_THREAD_ID, threadId, attributes);

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		msgArtifact.addAttributes(attributes);

		// create sender/recipient relationships  
		try {
			getSleuthkitCase().getCommunicationsManager().addRelationships(senderAccountInstance,
					recipientAccountsList, msgArtifact, Relationship.Type.MESSAGE, dateTime);
		} catch (TskDataException ex) {
			throw new TskCoreException(String.format("Failed to create Message relationships between sender account = %s and recipients = %s.",
					senderAccountInstance.getAccount().getTypeSpecificID(), recipientsStr), ex);
		}

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(msgArtifact, getModuleName());

		// return the artifact
		return msgArtifact;
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/callee, and creates a
	 * relationship between the self account and the caller account as well
	 * between the self account and the callee account.
	 *
	 * @param direction     Call direction, UNKNOWN if not available.
	 * @param callerId      Caller id, may be null.
	 * @param calleeId      Callee id, may be null.
	 *
	 * At least one of the two must be provided - the caller Id, or a callee id.
	 *
	 * @param startDateTime Start date/time, 0 if not available.
	 * @param endDateTime   End date/time, 0 if not available.
	 * @param mediaType     Media type.
	 *
	 * @return Call log artifact.
	 *
	 * @throws TskCoreException    If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			String callerId, String calleeId,
			long startDateTime, long endDateTime, CallMediaType mediaType) throws TskCoreException, BlackboardException {
		return addCalllog(direction, callerId, calleeId,
				startDateTime, endDateTime, mediaType,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/callee, and creates a
	 * relationship between the self account and the caller account as well
	 * between the self account and the callee account.
	 *
	 * @param direction           Call direction, UNKNOWN if not available.
	 * @param callerId            Caller id, may be null.
	 * @param calleeId            Callee id, may be null.
	 *
	 * At least one of the two must be provided - the caller Id, or a callee id.
	 *
	 * @param startDateTime       Start date/time, 0 if not available.
	 * @param endDateTime         End date/time, 0 if not available.
	 * @param mediaType           Media type.
	 * @param otherAttributesList Other attributes.
	 *
	 * @return Call log artifact.
	 *
	 * @throws TskCoreException    If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			String callerId,
			String calleeId,
			long startDateTime, long endDateTime,
			CallMediaType mediaType,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {
		return addCalllog(direction,
				callerId,
				Arrays.asList(calleeId),
				startDateTime, endDateTime,
				mediaType,
				otherAttributesList);
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/callees, and creates a
	 * relationship between the self account and the caller account as well
	 * between the self account and each callee account.
	 *
	 * @param direction     Call direction, UNKNOWN if not available.
	 * @param callerId      Caller id, may be null.
	 * @param calleeIdsList Callee list, may be an empty list.
	 *
	 * At least one of the two must be provided - the caller Id, or a callee id.
	 *
	 * @param startDateTime Start date/time, 0 if not available.
	 * @param endDateTime   End date/time, 0 if not available.
	 * @param mediaType     Call media type, UNKNOWN if not available.
	 *
	 * @return Call log artifact.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			String callerId,
			Collection<String> calleeIdsList,
			long startDateTime, long endDateTime,
			CallMediaType mediaType) throws TskCoreException, BlackboardException {

		return addCalllog(direction, callerId, calleeIdsList,
				startDateTime, endDateTime,
				mediaType,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller and each of the callees,
	 * and creates relationships between caller and callees.
	 *
	 * @param direction           Call direction, UNKNOWN if not available.
	 * @param callerId            Caller id, required for incoming call.
	 * @param calleeIdsList       Callee ids list, required for an outgoing
	 *                            call.
	 *
	 * At least one of the two must be provided - the caller Id, or a callee id.
	 *
	 * @param startDateTime       Start date/time, 0 if not available.
	 * @param endDateTime         End date/time, 0 if not available.
	 * @param mediaType           Call media type, UNKNOWN if not available.
	 * @param otherAttributesList other attributes, can be an empty list
	 *
	 * @return Call log artifact.
	 *
	 * @throws TskCoreException    If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			String callerId,
			Collection<String> calleeIdsList,
			long startDateTime, long endDateTime,
			CallMediaType mediaType,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		// Either caller id or a callee id must be provided.
		if (StringUtils.isEmpty(callerId) && (isEffectivelyEmpty(calleeIdsList))) {
			throw new IllegalArgumentException("Either a caller id, or at least one callee id must be provided for a call log.");
		}

		BlackboardArtifact callLogArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// Create TSK_CALLLOG artifact
		callLogArtifact = getContent().newArtifact(ARTIFACT_TYPE.TSK_CALLLOG);

		// Add basic attributes 
		addAttributeIfNotZero(ATTRIBUTE_TYPE.TSK_DATETIME_START, startDateTime, attributes);
		addAttributeIfNotZero(ATTRIBUTE_TYPE.TSK_DATETIME_END, endDateTime, attributes);
		addCommDirectionIfKnown(direction, attributes);

		// set FROM attribute and create a caller account
		AccountFileInstance callerAccountInstance;
		if (StringUtils.isEmpty(callerId)) {
			// for an Outgoing call, if no caller is specified, assume self account is the caller
			if (direction == CommunicationDirection.OUTGOING) {
				callerAccountInstance = getSelfAccountInstance();
				addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, getSelfAccountInstance().getAccount().getTypeSpecificID(), attributes);
			} else { // incoming call without a caller id
				throw new IllegalArgumentException("Caller Id not provided for incoming call.");
			}
		} else {
			callerAccountInstance = createAccountInstance(moduleAccountsType, callerId);
			addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, callerId, attributes);
		}

		// Create a comma separated string of callee
		List<AccountFileInstance> recipientAccountsList = new ArrayList<>();
		String calleesStr = "";
		if (!isEffectivelyEmpty(calleeIdsList)) {
			calleesStr = addressListToString(calleeIdsList);
			addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, calleesStr, attributes);

			for (String callee : calleeIdsList) {
				if (!StringUtils.isEmpty(callee)) {
					recipientAccountsList.add(createAccountInstance(moduleAccountsType, callee));
				}
			}
		} else {
			// For incoming call, if no callee specified, assume self account is callee
			if (direction == CommunicationDirection.INCOMING) {
				addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, getSelfAccountInstance().getAccount().getTypeSpecificID(), attributes);
				recipientAccountsList.add(getSelfAccountInstance());
			} else { // outgoing call without any callee
				throw new IllegalArgumentException("Callee not provided for an outgoing call.");
			}
		}

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		callLogArtifact.addAttributes(attributes);

		// create relationships between caller/callees
		try {
			getSleuthkitCase().getCommunicationsManager().addRelationships(callerAccountInstance,
					recipientAccountsList, callLogArtifact, Relationship.Type.CALL_LOG, startDateTime);
		} catch (TskDataException ex) {
			throw new TskCoreException(String.format("Failed to create Call log relationships between caller account = %s and callees = %s.",
					callerAccountInstance.getAccount(), calleesStr), ex);
		}

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(callLogArtifact, getModuleName());

		// return the artifact
		return callLogArtifact;
	}

	/**
	 * Adds attachments to a message.
	 *
	 * @param message     Message artifact.
	 * @param attachments Attachments to add to the message.
	 *
	 * @throws TskCoreException If there is an error in adding attachments
	 */
	public void addAttachments(BlackboardArtifact message, MessageAttachments attachments) throws TskCoreException {

		// Convert the MessageAttachments object to JSON string
		Gson gson = new Gson();
		String attachmentsJson = gson.toJson(attachments);

		// Create attribute 
		message.addAttribute(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ATTACHMENTS, getModuleName(), attachmentsJson));

		// Associate each attachment file with the message.
		Collection<FileAttachment> fileAttachments = attachments.getFileAttachments();
		for (FileAttachment fileAttachment : fileAttachments) {
			long attachedFileObjId = fileAttachment.getObjectId();
			if (attachedFileObjId >= 0) {
				AbstractFile attachedFile = message.getSleuthkitCase().getAbstractFileById(attachedFileObjId);
				associateAttachmentWithMessage(message, attachedFile);
			}
		}
	}

	/**
	 * Creates a TSK_ASSOCIATED_OBJECT artifact between the attachment file and
	 * the message.
	 *
	 * @param message     Message artifact.
	 * @param attachments Attachment file.
	 *
	 * @return TSK_ASSOCIATED_OBJECT artifact.
	 *
	 * @throws TskCoreException If there is an error creating the
	 *                          TSK_ASSOCIATED_OBJECT artifact.
	 */
	private BlackboardArtifact associateAttachmentWithMessage(BlackboardArtifact message, AbstractFile attachedFile) throws TskCoreException {
		Collection<BlackboardAttribute> attributes = new ArrayList<>();
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ASSOCIATED_ARTIFACT, this.getModuleName(), message.getArtifactID()));

		BlackboardArtifact bba = attachedFile.newArtifact(ARTIFACT_TYPE.TSK_ASSOCIATED_OBJECT);
		bba.addAttributes(attributes); //write out to bb
		return bba;
	}
	
	/**
	 * Converts a list of ids into a single comma separated string.
	 */
	private String addressListToString(Collection<String> addressList) {

		String toAddresses = "";
		if (addressList != null && (!addressList.isEmpty())) {
			StringBuilder toAddressesSb = new StringBuilder();
			for (String address : addressList) {
				if (!StringUtils.isEmpty(address)) {
					toAddressesSb = toAddressesSb.length() > 0 ? toAddressesSb.append(", ").append(address) : toAddressesSb.append(address);
				}
			}
			toAddresses = toAddressesSb.toString();
		}

		return toAddresses;
	}

	/**
	 * Checks if the given list of ids has at least one non-null non-blank id.
	 *
	 * @param addressList List of string ids.
	 *
	 * @return false if the list has at least one non-null non-blank id,
	 *         otherwise true.
	 *
	 */
	private boolean isEffectivelyEmpty(Collection<String> idList) {

		if (idList == null || idList.isEmpty()) {
			return true;
		}

		for (String id : idList) {
			if (!StringUtils.isEmpty(id)) {
				return false;
			}
		}

		return true;

	}

	/**
	 * Adds communication direction attribute to the list, if it is not unknown.
	 */
	private void addCommDirectionIfKnown(CommunicationDirection direction, Collection<BlackboardAttribute> attributes) {
		if (direction != CommunicationDirection.UNKNOWN) {
			attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DIRECTION, getModuleName(), direction.getDisplayName()));
		}
	}

	/**
	 * Adds message read status attribute to the list, if it is not unknown.
	 */
	private void addMessageReadStatusIfKnown(MessageReadStatus readStatus, Collection<BlackboardAttribute> attributes) {
		if (readStatus != MessageReadStatus.UNKNOWN) {
			attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_READ_STATUS, getModuleName(), (readStatus == MessageReadStatus.READ) ? 1 : 0));
		}
	}

	/**
	 * Returns self account instance.  Lazily creates it if one doesn't exist yet.
	 * 
	 * @return Self account instance.
	 * @throws TskCoreException 
	 */
	private synchronized AccountFileInstance getSelfAccountInstance() throws TskCoreException {
		if (selfAccountInstance == null) {
			selfAccountInstance = getSleuthkitCase().getCommunicationsManager().createAccountFileInstance(selfAccountType, selfAccountId, this.getModuleName(), getContent());
		}
		return selfAccountInstance;
	}
}
