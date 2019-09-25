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
	private final AccountFileInstance selfAccountInstance;

	// Type of accounts to be created for the module using this helper.
	private final Account.Type accountsType;

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
	 * @param srcFile      Source file being processed by the module.
	 * @param accountsType Account type {@link Account.Type} created by this
	 *                     module.
	 *
	 * @throws TskCoreException If there is an error creating the device
	 *                          account.
	 */
	public CommunicationArtifactsHelper(SleuthkitCase caseDb,
			String moduleName, AbstractFile srcFile, Account.Type accountsType) throws TskCoreException {

		super(caseDb, moduleName, srcFile);

		this.accountsType = accountsType;
		this.selfAccountInstance = getSleuthkitCase().getCommunicationsManager().createAccountFileInstance(Account.Type.DEVICE, ((DataSource) getAbstractFile().getDataSource()).getDeviceId(), moduleName, getAbstractFile());
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
	 * @param caseDb             Sleuthkit case db.
	 * @param moduleName         Name of module using the helper.
	 * @param srcFile            Source file being processed by the module.
	 * @param accountsType		 Account type {@link Account.Type} created by
	 *                           this module.
	 * @param selfAccountType    Self account type to be created for this
	 *                           module.
	 * @param selfAccountAddress Account unique id for the self account.
	 *
	 * @throws TskCoreException	If there is an error creating the self account
	 */
	public CommunicationArtifactsHelper(SleuthkitCase caseDb, String moduleName, AbstractFile srcFile, Account.Type accountsType, Account.Type selfAccountType, Account.Address selfAccountAddress) throws TskCoreException {

		super(caseDb, moduleName, srcFile);

		this.accountsType = accountsType;
		this.selfAccountInstance = getSleuthkitCase().getCommunicationsManager().createAccountFileInstance(selfAccountType, selfAccountAddress.getUniqueID(), moduleName, getAbstractFile());
	}

	/**
	 * Creates and adds a TSK_CONTACT artifact to the case, with specified
	 * attributes. Also creates an account instance of specified type for the
	 * contact with the specified ID.
	 *
	 * @param contactAccountUniqueID Unique id for contact account, required.
	 * @param contactName            Name of contact, required.
	 * @param phoneNumber            Primary phone number for contact, may be
	 *                               empty or null.
	 * @param homePhoneNumber        Home phone number, may be empty or null.
	 * @param mobilePhoneNumber      Mobile phone number, may be empty or null.
	 * @param emailAddr              Email address for the contact, may be empty
	 *                               or null.
	 *
	 * @return Contact artifact created.
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 *
	 */
	public BlackboardArtifact addContact(String contactAccountUniqueID, String contactName,
			String phoneNumber, String homePhoneNumber,
			String mobilePhoneNumber, String emailAddr) throws TskCoreException, BlackboardException {
		return addContact(contactAccountUniqueID, contactName, phoneNumber,
				homePhoneNumber, mobilePhoneNumber, emailAddr,
				Collections.emptyList());
	}

	/**
	 * Creates and adds a TSK_CONTACT artifact to the case, with specified
	 * attributes. Also creates an account instance for the contact with the
	 * specified ID.
	 *
	 * @param contactAccountUniqueID Unique id for contact account, required.
	 * @param contactName            Name of contact, required.
	 * @param phoneNumber            Primary phone number for contact, may be
	 *                               empty or null.
	 * @param homePhoneNumber        Home phone number, may be empty or null.
	 * @param mobilePhoneNumber      Mobile phone number, may be empty or null.
	 * @param emailAddr              Email address for the contact, may be empty
	 *                               or null.
	 *
	 * @param additionalAttributes   Additional attributes for contact, may be
	 *                               an empty list.
	 *
	 * @return contact artifact created.
	 *
	 * @throws TskCoreException		If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 *
	 */
	public BlackboardArtifact addContact(String contactAccountUniqueID, String contactName,
			String phoneNumber, String homePhoneNumber,
			String mobilePhoneNumber, String emailAddr,
			Collection<BlackboardAttribute> additionalAttributes) throws TskCoreException, BlackboardException {

		BlackboardArtifact contactArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create TSK_CONTACT artifact
		contactArtifact = getAbstractFile().newArtifact(ARTIFACT_TYPE.TSK_CONTACT);

		// construct attributes
		attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), contactName));

		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, phoneNumber, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_HOME, homePhoneNumber, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_MOBILE, mobilePhoneNumber, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_EMAIL, emailAddr, attributes);

		// add attributes
		attributes.addAll(additionalAttributes);
		contactArtifact.addAttributes(attributes);

		// Find/Create an account instance for the contact
		// Create a relationship between selfAccount and contactAccount
		AccountFileInstance contactAccountInstance = createAccountInstance(accountsType, contactAccountUniqueID);
		addRelationship(selfAccountInstance, contactAccountInstance, contactArtifact, Relationship.Type.CONTACT, 0);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(contactArtifact, getModuleName());

		return contactArtifact;
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
		return getSleuthkitCase().getCommunicationsManager().createAccountFileInstance(accountType, accountUniqueID, getModuleName(), getAbstractFile());
	}

	/**
	 * Adds a relations between the two specified account instances.
	 *
	 * @param selfAccount      'Self' account.
	 * @param otherAccount     Other account.
	 * @param sourceArtifact   Artifact from which the relationship is derived.
	 * @param relationshipType Type of relationship.
	 * @param dateTime         Date/time of relationship.
	 *
	 * @throws TskCoreException If there is an error creating relationship.
	 */
	private void addRelationship(AccountFileInstance selfAccountInstance, AccountFileInstance otherAccountInstance,
			BlackboardArtifact sourceArtifact, Relationship.Type relationshipType, long dateTime) throws TskCoreException {

		// create a relationship only if the selfAccount and otherAccount are not one and the same
		if (selfAccountInstance.getAccount().equals(otherAccountInstance.getAccount()) == false) {
			try {
				getSleuthkitCase().getCommunicationsManager().addRelationships(selfAccountInstance,
						Collections.singletonList(otherAccountInstance), sourceArtifact, relationshipType, dateTime);
			} catch (TskDataException ex) {
				throw new TskCoreException(String.format("Failed to create relationship between account = %s and account = %s.",
						selfAccountInstance.getAccount(), otherAccountInstance.getAccount()), ex);
			}
		}
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates an account instance for the sender/receiver, and creates a
	 * relationship between the self account and the sender/receiver account.
	 *
	 * @param messageType Message type, required.
	 * @param direction   Message direction, UNKNOWN if not available.
	 * @param fromAddress Sender address, may be null.
	 * @param toAddress	  Recipient address, may be null.
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
			Account.Address fromAddress,
			Account.Address toAddress,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText, String threadId) throws TskCoreException, BlackboardException {
		return addMessage(messageType, direction,
				fromAddress, toAddress, dateTime, readStatus,
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
	 * @param fromAddress         Sender address, may be null.
	 * @param toAddress	          Recipient address, may be null.
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
			Account.Address fromAddress,
			Account.Address toAddress,
			long dateTime, MessageReadStatus readStatus, String subject,
			String messageText, String threadId,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		return addMessage(messageType, direction,
				fromAddress,
				Arrays.asList(toAddress),
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
	 * @param messageType    Message type, required.
	 * @param direction      Message direction, UNKNOWN if not available.
	 * @param fromAddress    Sender address, may be null.
	 * @param recipientsList Recipient address list, may be null or empty an
	 *                       list.
	 * @param dateTime       Date/time of message, 0 if not available.
	 * @param readStatus     Message read status, UNKNOWN if not available.
	 * @param subject        Message subject, may be empty or null.
	 * @param messageText    Message body, may be empty or null.
	 * @param threadId       Message thread id, may be empty or null.
	 *
	 * @return Message artifact.
	 *
	 * @throws TskCoreException		  If there is an error creating the artifact.
	 * @throws BlackboardException	If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addMessage(String messageType,
			CommunicationDirection direction,
			Account.Address fromAddress,
			List<Account.Address> recipientsList,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText, String threadId) throws TskCoreException, BlackboardException {
		return addMessage(messageType, direction,
				fromAddress, recipientsList,
				dateTime, readStatus,
				subject, messageText, threadId,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates an account instance for the sender/receivers, and creates a
	 * relationship between the self account and the sender/receivers account.
	 *
	 * @param messageType         Message type, required.
	 * @param direction           Message direction, UNKNOWN if not available.
	 * @param fromAddress         Sender address, may be null.
	 * @param recipientsList      Recipient address list, may be null or empty
	 *                            an list.
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
			Account.Address fromAddress,
			List<Account.Address> recipientsList,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText,
			String threadId,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		// Created message artifact.  
		BlackboardArtifact msgArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create TSK_MESSAGE artifact
		msgArtifact = getAbstractFile().newArtifact(ARTIFACT_TYPE.TSK_MESSAGE);

		// construct attributes
		attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE, getModuleName(), messageType));
		addAttributeIfNotZero(ATTRIBUTE_TYPE.TSK_DATETIME, dateTime, attributes);

		addMessageReadStatusIfKnown(readStatus, attributes);
		addCommDirectionIfKnown(direction, attributes);

		if (fromAddress != null && !StringUtils.isEmpty(fromAddress.getDisplayName())) {
			attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, getModuleName(), fromAddress.getDisplayName()));
		}
		// Create a comma separated string of recipients
		String toAddresses = addressListToString(recipientsList);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, toAddresses, attributes);

		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_SUBJECT, subject, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_TEXT, messageText, attributes);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_THREAD_ID, threadId, attributes);

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		msgArtifact.addAttributes(attributes);

		// create account and relationship with sender
		createSenderAccountAndRelationship(fromAddress, msgArtifact, Relationship.Type.MESSAGE, dateTime);

		// create account and relationship with each recipient  
		createRecipientAccountsAndRelationships(recipientsList, msgArtifact, Relationship.Type.MESSAGE, dateTime);

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
	 * @param fromAddress   Caller address, may be null.
	 * @param toAddress			  Callee address, may be null.
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
			Account.Address fromAddress, Account.Address toAddress,
			long startDateTime, long endDateTime, CallMediaType mediaType) throws TskCoreException, BlackboardException {
		return addCalllog(direction, fromAddress, toAddress,
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
	 * @param fromAddress         Caller address, may be null.
	 * @param toAddress			        Callee address, may be null.
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
			Account.Address fromAddress,
			Account.Address toAddress,
			long startDateTime, long endDateTime,
			CallMediaType mediaType,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {
		return addCalllog(direction,
				fromAddress,
				Arrays.asList(toAddress),
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
	 * @param fromAddress   Caller address, may be null.
	 * @param toAddressList callee address list, may be an empty list.
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
			Account.Address fromAddress,
			Collection<Account.Address> toAddressList,
			long startDateTime, long endDateTime,
			CallMediaType mediaType) throws TskCoreException, BlackboardException {

		return addCalllog(direction, fromAddress, toAddressList,
				startDateTime, endDateTime,
				mediaType,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/callees, and creates a
	 * relationship between the self account and the caller account as well
	 * between the self account and each callee account.
	 *
	 * @param direction           Call direction, UNKNOWN if not available.
	 * @param fromAddress         Caller address, may be null.
	 * @param toAddressList       callee address list, may be an empty list.
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
			Account.Address fromAddress,
			Collection<Account.Address> toAddressList,
			long startDateTime, long endDateTime,
			CallMediaType mediaType,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {
		BlackboardArtifact callLogArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// Create TSK_CALLLOG artifact
		callLogArtifact = getAbstractFile().newArtifact(ARTIFACT_TYPE.TSK_CALLLOG);

		// Add basic attributes 
		addAttributeIfNotZero(ATTRIBUTE_TYPE.TSK_DATETIME_START, startDateTime, attributes);
		addAttributeIfNotZero(ATTRIBUTE_TYPE.TSK_DATETIME_END, endDateTime, attributes);
		addCommDirectionIfKnown(direction, attributes);

		if (fromAddress != null) {
			addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, fromAddress.getUniqueID(), attributes);
			addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_NAME, fromAddress.getDisplayName(), attributes);
		}

		// Create a comma separated string of recipients
		String toAddresses = addressListToString(toAddressList);
		addAttributeIfNotNull(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, toAddresses, attributes);

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		callLogArtifact.addAttributes(attributes);

		// Create a relationship between selfAccount and caller
		createSenderAccountAndRelationship(fromAddress, callLogArtifact, Relationship.Type.CALL_LOG, startDateTime);

		// Create a relationship between selfAccount and each callee
		createRecipientAccountsAndRelationships(toAddressList, callLogArtifact, Relationship.Type.CALL_LOG, startDateTime);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(callLogArtifact, getModuleName());

		// return the artifact
		return callLogArtifact;
	}

	/**
	 * Converts a list of addresses into a single comma separated string of
	 * addresses.
	 */
	private String addressListToString(Collection<Account.Address> addressList) {

		String toAddresses = "";
		if (addressList != null && (!addressList.isEmpty())) {
			StringBuilder toAddressesSb = new StringBuilder();
			for (Account.Address address : addressList) {
				String displayAddress = !StringUtils.isEmpty(address.getDisplayName()) ? address.getDisplayName() : address.getUniqueID();
				toAddressesSb = toAddressesSb.length() > 0 ? toAddressesSb.append(",").append(displayAddress) : toAddressesSb.append(displayAddress);
			}
			toAddresses = toAddressesSb.toString();
		}

		return toAddresses;
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
	 * Creates an account & relationship for sender, if the sender address is
	 * not null/empty.
	 */
	private void createSenderAccountAndRelationship(Account.Address fromAddress,
			BlackboardArtifact artifact, Relationship.Type relationshipType, long dateTime) throws TskCoreException {
		if (fromAddress != null) {
			AccountFileInstance senderAccountInstance = createAccountInstance(accountsType, fromAddress.getUniqueID());

			// Create a relationship between selfAccount and sender account
			addRelationship(selfAccountInstance, senderAccountInstance, artifact, relationshipType, dateTime);
		}
	}

	/**
	 * Creates accounts & relationship with each recipient, if the recipient
	 * list is not null/empty.
	 */
	private void createRecipientAccountsAndRelationships(Collection<Account.Address> toAddressList,
			BlackboardArtifact artifact, Relationship.Type relationshipType, long dateTime) throws TskCoreException {
		// Create a relationship between selfAccount and each recipient
		if (toAddressList != null) {
			for (Account.Address recipient : toAddressList) {
				AccountFileInstance calleeAccountInstance = createAccountInstance(accountsType, recipient.getUniqueID());
				addRelationship(selfAccountInstance, calleeAccountInstance, artifact, relationshipType, (dateTime > 0) ? dateTime : 0);
			}
		}
	}

}
