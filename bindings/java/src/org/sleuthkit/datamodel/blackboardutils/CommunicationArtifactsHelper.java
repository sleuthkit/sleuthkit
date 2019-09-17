/*
 * Autopsy Forensic Browser
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
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Account;
import org.sleuthkit.datamodel.AccountFileInstance;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.DataSource;
import org.sleuthkit.datamodel.Relationship;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskDataException;

/**
 * A helper class to support modules that parse SQLite databases from mobile
 * apps and create artifacts.
 */
public final class CommunicationArtifactsHelper extends ArtifactHelper {

	private static final Logger logger = Logger.getLogger(CommunicationArtifactsHelper.class.getName());

	/**
	 * Enum for message read status
	 */
	public enum MessageReadStatus {

		UNKNOWN, /// read status is unknown
		UNREAD, /// message has not been read
		READ        /// message has been read
	}

	/**
	 * Enum for call/message direction
	 */
	public enum CommunicationDirection {
		UNKNOWN("Unknown"),
		INCOMING("Incoming"),
		OUTGOING("Outgoing");

		private final String dirStr;

		CommunicationDirection(String dir) {
			this.dirStr = dir;
		}

		public String getString() {
			return dirStr;
		}
	}

	/**
	 * Enum for call media type
	 */
	public enum CallMediaType {
		UNKNOWN("Unknown"),
		AUDIO("Audio"),
		VIDEO("Video");

		private final String typeStr;

		CallMediaType(String type) {
			this.typeStr = type;
		}

		public String getString() {
			return typeStr;
		}
	}

	// 'self' account for the application. 
	private final AccountFileInstance selfAccountInstance;

	// type of accounts to be created for the Application using this helper
	private final Account.Type accountsType;

	/**
	 * Constructs a AppDB parser helper for the given DB file.
	 *
	 * This is a constructor for Apps that that do not have any app specific
	 * account information for device owner and will use a 'Device' account in
	 * lieu.
	 *
	 * It creates a DeviceAccount instance to use as a self account.
	 *
	 * @param caseDb       Sleuthkit case db
	 * @param moduleName   name module using the helper
	 * @param srcFile      source file being processed by the module
	 * @param accountsType account types created by this module
	 *
	 * @throws TskCoreException
	 */
	public CommunicationArtifactsHelper(SleuthkitCase caseDb, String moduleName, AbstractFile srcFile, Account.Type accountsType) throws TskCoreException {

		super(caseDb, moduleName, srcFile);

		this.accountsType = accountsType;
		this.selfAccountInstance = getSleuthkitCase().getCommunicationsManager().createAccountFileInstance(Account.Type.DEVICE, ((DataSource) getAbstractFile().getDataSource()).getDeviceId(), moduleName, getAbstractFile());
	}

	/**
	 * Constructs a AppDB parser helper for the given DB file.
	 *
	 * This constructor is for Apps that do have app specific account
	 * information for the device owner to create a 'self' account.
	 *
	 * It creates a an account instance with specified type & id and uses it as
	 * a self account.
	 *
	 * @param caseDb             Sleuthkit case db
	 * @param moduleName         name module using the helper
	 * @param srcFile            source file being processed by the module
	 * @param accountsType       account types created by this module
	 * @param selfAccountType    self account type to be created for this module
	 * @param selfAccountAddress account unique id for the self account
	 *
	 * @throws TskCoreException
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
	 * @param contactAccountUniqueID unique id for contact account
	 * @param contactName            Name of contact, required
	 * @param phoneNumber            primary phone number for contact, may be
	 *                               empty or null
	 * @param homePhoneNumber        home phone number, may be empty or null
	 * @param mobilePhoneNumber      mobile phone number, may be empty or null
	 * @param emailAddr              Email address for contact, may be empty or
	 *                               null
	 *
	 * @return artifact created
	 *
	 */
	public BlackboardArtifact addContact(String contactAccountUniqueID, String contactName,
			String phoneNumber, String homePhoneNumber,
			String mobilePhoneNumber, String emailAddr) {
		return addContact(contactAccountUniqueID, contactName, phoneNumber,
				homePhoneNumber, mobilePhoneNumber, emailAddr,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Creates and adds a TSK_CONTACT artifact to the case, with specified
	 * attributes. Also creates an account instance for the contact with the
	 * specified ID.
	 *
	 * @param contactAccountUniqueID unique id for contact account
	 * @param contactName            Name of contact, required
	 * @param phoneNumber            primary phone number for contact, may be
	 *                               empty or null
	 * @param homePhoneNumber        home phone number, may be empty or null
	 * @param mobilePhoneNumber      mobile phone number, may be empty or null
	 * @param emailAddr              Email address for contact, may be empty or
	 *                               null
	 *
	 * @param additionalAttributes   additional attributes for contact, may be
	 *                               an empty list
	 *
	 * @return contact artifact created
	 *
	 */
	public BlackboardArtifact addContact(String contactAccountUniqueID, String contactName,
			String phoneNumber, String homePhoneNumber,
			String mobilePhoneNumber, String emailAddr,
			Collection<BlackboardAttribute> additionalAttributes) {

		BlackboardArtifact contactArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();

			// Create TSK_CONTACT artifact
			contactArtifact = getAbstractFile().newArtifact(ARTIFACT_TYPE.TSK_CONTACT);

			// Add basic attributes for name phonenumber email, if specified
			attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), contactName));

			addAttributeIfNotNull(phoneNumber, ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, attributes);
			addAttributeIfNotNull(homePhoneNumber, ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_HOME, attributes);
			addAttributeIfNotNull(mobilePhoneNumber, ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_MOBILE, attributes);
			addAttributeIfNotNull(emailAddr, ATTRIBUTE_TYPE.TSK_EMAIL, attributes);

			contactArtifact.addAttributes(attributes);
			contactArtifact.addAttributes(additionalAttributes);

			// Find/Create an account instance for the contact
			// Create a relationship between selfAccount and contactAccount
			AccountFileInstance contactAccountInstance = createAccountInstance(accountsType, contactAccountUniqueID);
			addRelationship(selfAccountInstance, contactAccountInstance, contactArtifact, Relationship.Type.CONTACT, 0);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(contactArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add contact artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((contactArtifact != null) ? contactArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		return contactArtifact;
	}

	/**
	 * Creates an account file instance associated with the DB file.
	 *
	 * @param accountType     type of account to create
	 * @param accountUniqueID unique id for the account
	 *
	 * @return account instance created
	 *
	 * @throws TskCoreException
	 */
	private AccountFileInstance createAccountInstance(Account.Type accountType, String accountUniqueID) throws TskCoreException {
		return getSleuthkitCase().getCommunicationsManager().createAccountFileInstance(accountType, accountUniqueID, getModuleName(), getAbstractFile());
	}

	/**
	 * Adds a relations between the two specified account instances.
	 *
	 * @param selfAccount      device owner account
	 * @param otherAccount     other account
	 * @param sourceArtifact   artifact from which relationship is derived.
	 * @param relationshipType type of relationship
	 * @param dateTime         date/time of relationship
	 */
	private void addRelationship(AccountFileInstance selfAccountInstance, AccountFileInstance otherAccountInstance,
			BlackboardArtifact sourceArtifact, Relationship.Type relationshipType, long dateTime) {
		try {
			if (selfAccountInstance.getAccount() != otherAccountInstance.getAccount()) {
				getSleuthkitCase().getCommunicationsManager().addRelationships(selfAccountInstance,
						Collections.singletonList(otherAccountInstance), sourceArtifact, relationshipType, dateTime);
			}
		} catch (TskCoreException | TskDataException ex) {
			logger.log(Level.SEVERE, String.format("Unable to add relationship between account %s and account %s", selfAccountInstance.toString(), otherAccountInstance.toString()), ex); //NON-NLS
		}
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates an account instance for the sender/receiver, and creates a
	 * relationship between the self account and the sender/receiver account.
	 *
	 * @param messageType message type, may be empty or null
	 * @param direction   message direction, UNKNOWN if not available
	 * @param fromAddress sender address, may be null
	 * @param toAddress   recipient address, may be null
	 * @param dateTime    date/time of message, 0 if not available
	 * @param readStatus  message read or not, UNKNOWN if not available
	 * @param subject     message subject, may be empty or null
	 * @param messageText message body, may be empty or null
	 * @param threadId,   message thread id, may be empty or null
	 *
	 * @return message artifact
	 */
	public BlackboardArtifact addMessage(
			String messageType,
			CommunicationDirection direction,
			Account.Address fromAddress,
			Account.Address toAddress,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText, String threadId) {
		return addMessage(messageType, direction,
				fromAddress, toAddress, dateTime, readStatus,
				subject, messageText, threadId,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates an account instance for the sender/receiver, and creates a
	 * relationship between the self account and the sender/receiver account.
	 *
	 * @param messageType         message type, may be empty or null
	 * @param direction           message direction, UNKNOWN if not available
	 * @param fromAddress         sender address, may be null
	 * @param toAddress           recipient address, may be null
	 * @param dateTime            date/time of message, 0 if not available
	 * @param readStatus          message read or not, UNKNOWN if not available
	 * @param subject             message subject, may be empty or null
	 * @param messageText         message body, may be empty or null
	 * @param threadId,           message thread id, may be empty or null
	 * @param otherAttributesList additional attributes, may be an empty list
	 *
	 * @return message artifact
	 */
	public BlackboardArtifact addMessage(String messageType,
			CommunicationDirection direction,
			Account.Address fromAddress,
			Account.Address toAddress,
			long dateTime, MessageReadStatus readStatus, String subject,
			String messageText, String threadId,
			Collection<BlackboardAttribute> otherAttributesList) {

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
	 * relationship between the self account and the sender/receiver account.
	 *
	 * This method is for messages with a multiple recipients.
	 *
	 * @param messageType    message type, may be empty or null
	 * @param direction      message direction, UNKNOWN if not available
	 * @param fromAddress    sender address, may be null
	 * @param recipientsList recipient address list, may be null or empty list
	 * @param dateTime       date/time of message, 0 if not available
	 * @param readStatus     message read or not, UNKNOWN if not available
	 * @param subject        message subject, may be empty or null
	 * @param messageText    message body, may be empty or null
	 * @param threadId,      message thread id, may be empty or null
	 *
	 *
	 * @return message artifact
	 */
	public BlackboardArtifact addMessage(String messageType,
			CommunicationDirection direction,
			Account.Address fromAddress,
			List<Account.Address> recipientsList,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText, String threadId) {
		return addMessage(messageType, direction,
				fromAddress, recipientsList,
				dateTime, readStatus,
				subject, messageText, threadId,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a TSK_MESSAGE artifact.
	 *
	 * Also creates an account instance for the sender/receiver, and creates a
	 * relationship between the self account and the sender/receiver account.
	 *
	 * This method is for messages with a multiple recipients.
	 *
	 * @param messageType         message type, may be empty or null
	 * @param direction           message direction, UNKNOWN if not available
	 * @param fromAddress         sender address, may be null
	 * @param recipientsList      recipient address list, may be null or empty
	 *                            list
	 * @param dateTime            date/time of message, 0 if not available
	 * @param readStatus          message read or not, UNKNOWN if not available
	 * @param subject             message subject, may be empty or null
	 * @param messageText         message body, may be empty or null
	 * @param threadId,           message thread id, may be empty or null
	 * @param otherAttributesList other attributes, may be an empty list
	 *
	 *
	 * @return message artifact
	 */
	public BlackboardArtifact addMessage(String messageType,
			CommunicationDirection direction,
			Account.Address fromAddress,
			List<Account.Address> recipientsList,
			long dateTime, MessageReadStatus readStatus,
			String subject, String messageText,
			String threadId,
			Collection<BlackboardAttribute> otherAttributesList) {

		// Created message artifact.  
		BlackboardArtifact msgArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();

			// Create TSK_MESSAGE artifact
			msgArtifact = getAbstractFile().newArtifact(ARTIFACT_TYPE.TSK_MESSAGE);

			addAttributeIfNotZero(dateTime, ATTRIBUTE_TYPE.TSK_DATETIME, attributes);
			addMessageReadStatusIfKnown(readStatus, attributes);
			addAttributeIfNotNull(messageType, ATTRIBUTE_TYPE.TSK_MESSAGE_TYPE, attributes);
			addCommDirectionIfKnown(direction, attributes);

			if (fromAddress != null && !StringUtils.isEmpty(fromAddress.getDisplayName())) {
				attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, getModuleName(), fromAddress.getDisplayName()));
			}
			// Create a comma separated string of recipients
			String toAddresses = addressListToString(recipientsList);
			addAttributeIfNotNull(toAddresses, ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, attributes);

			addAttributeIfNotNull(subject, ATTRIBUTE_TYPE.TSK_SUBJECT, attributes);
			addAttributeIfNotNull(messageText, ATTRIBUTE_TYPE.TSK_TEXT, attributes);
			addAttributeIfNotNull(threadId, ATTRIBUTE_TYPE.TSK_THREAD_ID, attributes);

			// Add other specified attributes
			msgArtifact.addAttributes(attributes);
			msgArtifact.addAttributes(otherAttributesList);

			// Find/create an account instance for sender
			createSenderAccountAndRelationship(fromAddress, msgArtifact, Relationship.Type.MESSAGE, dateTime);

			// Find/create an account instance for each recipient  
			createRecipientAccountsAndRelationships(recipientsList, msgArtifact, Relationship.Type.MESSAGE, dateTime);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(msgArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add message artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((msgArtifact != null) ? msgArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		// return the artifact
		return msgArtifact;
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/callee, and creates a
	 * relationship between the self account and the caller/callee account.
	 *
	 * @param direction     call direction
	 * @param fromAddress   caller address, may be empty
	 * @param toAddress     callee address, may be empty
	 * @param startDateTime start date/time
	 * @param endDateTime   end date/time
	 *
	 * @return call log artifact
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			Account.Address fromAddress, Account.Address toAddress,
			long startDateTime, long endDateTime) {
		return addCalllog(direction, fromAddress, toAddress,
				startDateTime, endDateTime,
				CallMediaType.UNKNOWN);
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/callee, and creates a
	 * relationship between the self account and the caller/callee account.
	 *
	 * @param direction     call direction
	 * @param fromAddress   caller address, may be empty
	 * @param toAddress     callee address, may be empty
	 * @param startDateTime start date/time
	 * @param endDateTime   end date/time
	 * @param mediaType     media type
	 *
	 * @return call log artifact
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			Account.Address fromAddress, Account.Address toAddress,
			long startDateTime, long endDateTime, CallMediaType mediaType) {
		return addCalllog(direction, fromAddress, toAddress,
				startDateTime, endDateTime, mediaType,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/receiver, and creates a
	 * relationship between the self account and the caller/receiver account.
	 *
	 * @param direction           call direction
	 * @param fromAddress         caller address, may be empty
	 * @param toAddress           callee address, may be empty
	 * @param startDateTime       start date/time
	 * @param endDateTime         end date/time
	 * @param mediaType           media type
	 * @param otherAttributesList other attributes
	 *
	 * @return call log artifact
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			Account.Address fromAddress,
			Account.Address toAddress,
			long startDateTime, long endDateTime,
			CallMediaType mediaType,
			Collection<BlackboardAttribute> otherAttributesList) {
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
	 * relationship between the device owner account and the caller account as
	 * well between the device owner account and each callee account
	 *
	 * @param direction     call direction, UNKNOWN if not available
	 * @param fromAddress   caller address, may be empty
	 * @param toAddressList callee address list, may be empty
	 * @param startDateTime start date/time, 0 if not available
	 * @param endDateTime   end date/time, 0 if not available
	 *
	 * @return call log artifact
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			Account.Address fromAddress,
			Collection<Account.Address> toAddressList,
			long startDateTime, long endDateTime) {

		return addCalllog(direction, fromAddress, toAddressList,
				startDateTime, endDateTime,
				CallMediaType.UNKNOWN);
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/callees, and creates a
	 * relationship between the device owner account and the caller account as
	 * well between the device owner account and each callee account
	 *
	 * @param direction     call direction, UNKNOWN if not available
	 * @param fromAddress   caller address, may be empty
	 * @param toAddressList callee address list, may be empty
	 * @param startDateTime start date/time, 0 if not available
	 * @param endDateTime   end date/time, 0 if not available
	 * @param mediaType     called media type, UNKNOWN if not available
	 *
	 * @return call log artifact
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			Account.Address fromAddress,
			Collection<Account.Address> toAddressList,
			long startDateTime, long endDateTime,
			CallMediaType mediaType) {

		return addCalllog(direction, fromAddress, toAddressList,
				startDateTime, endDateTime,
				mediaType,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a TSK_CALLLOG artifact.
	 *
	 * Also creates an account instance for the caller/callees, and creates a
	 * relationship between the device owner account and the caller account as
	 * well between the device owner account and each callee account
	 *
	 * @param direction           call direction, UNKNOWN if not available
	 * @param fromAddress         caller address, may be empty
	 * @param toAddressList       callee address list, may be empty
	 * @param startDateTime       start date/time, 0 if not available
	 * @param endDateTime         end date/time, 0 if not available
	 * @param mediaType           called media type, UNKNOWN if not available
	 * @param otherAttributesList other attributes, can be an empty list
	 *
	 * @return call log artifact
	 */
	public BlackboardArtifact addCalllog(CommunicationDirection direction,
			Account.Address fromAddress,
			Collection<Account.Address> toAddressList,
			long startDateTime, long endDateTime,
			CallMediaType mediaType,
			Collection<BlackboardAttribute> otherAttributesList) {
		BlackboardArtifact callLogArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();

			// Create TSK_CALLLOG artifact
			callLogArtifact = getAbstractFile().newArtifact(ARTIFACT_TYPE.TSK_CALLLOG);

			// Add basic attributes 
			addAttributeIfNotZero(startDateTime, ATTRIBUTE_TYPE.TSK_DATETIME_START, attributes);
			addAttributeIfNotZero(endDateTime, ATTRIBUTE_TYPE.TSK_DATETIME_END, attributes);
			addCommDirectionIfKnown(direction, attributes);

			if (fromAddress != null) {
				addAttributeIfNotNull(fromAddress.getUniqueID(), ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, attributes);
				addAttributeIfNotNull(fromAddress.getDisplayName(), ATTRIBUTE_TYPE.TSK_NAME, attributes);
			}

			// Create a comma separated string of recipients
			String toAddresses = addressListToString(toAddressList);
			addAttributeIfNotNull(toAddresses, ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, attributes);

			// Add attributes to artifact
			callLogArtifact.addAttributes(attributes);
			callLogArtifact.addAttributes(otherAttributesList);

			// Create a relationship between selfAccount and caller
			createSenderAccountAndRelationship(fromAddress, callLogArtifact, Relationship.Type.CALL_LOG, startDateTime);

			// Create a relationship between selfAccount and each callee
			createRecipientAccountsAndRelationships(toAddressList, callLogArtifact, Relationship.Type.CALL_LOG, startDateTime);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(callLogArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add calllog artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((callLogArtifact != null) ? callLogArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		// return the artifact
		return callLogArtifact;
	}

	/**
	 * Converts a list of addresses into a single comma separated string of
	 * addresses.
	 *
	 * @param addressList
	 *
	 * @return comma separated string of addresses
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
			attributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DIRECTION, getModuleName(), direction.getString()));
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
