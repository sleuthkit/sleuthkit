/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.EmailValidator;

/**
 * Provides general utility methods related to communications artifacts.
 */
public final class CommunicationsUtils {

	private static final String NON_DIGITS = "[^0-9]";
	private static final EmailValidator EMAIL_VALIDATOR = EmailValidator.getInstance(true, true);

	/**
	 * Empty private constructor.
	 */
	private CommunicationsUtils() {
	}

	/**
	 * Normalize the given phone number by removing all non numeric characters,
	 * except for a leading +.
	 *
	 * @param phoneNumber The phone number to normalize.
	 *
	 * @return The normalized phone number.
	 *
	 * @throws TskCoreException If the given string is not a valid phone number.
	 *
	 */
	public static String normalizePhoneNum(String phoneNumber) throws TskCoreException {
		if(StringUtils.isBlank(phoneNumber)) {
			return phoneNumber;
		}
		
		String phoneNumberWithOnlyDigits = phoneNumber.replaceAll(NON_DIGITS, "");

		if (phoneNumberWithOnlyDigits.isEmpty()) {
			return phoneNumber;
		} else if (phoneNumber.startsWith("+")) {
			return "+" + phoneNumberWithOnlyDigits;
		} else {
			return phoneNumberWithOnlyDigits;
		}
	}

	/**
	 * Normalizes the given email address by converting it to lowercase.
	 *
	 * @param emailAddress The email address string to be normalized.
	 *
	 * @return The normalized email address.
	 *
	 * @throws TskCoreException If the given string is not a valid email
	 *                          address.
	 */
	public static String normalizeEmailAddress(String emailAddress) throws TskCoreException {
		if(!StringUtils.isBlank(emailAddress)) {
			return emailAddress.toLowerCase();
		} else {
			return emailAddress;
		}
	}

	/**
	 * Checks if the given accountId is a valid id for the specified account
	 * type.
	 *
	 * @param accountType     Account type.
	 * @param accountUniqueID Id to check.
	 *
	 * @return True, if the id is a valid id for the given account type, False
	 *         otherwise.
	 */
	public static boolean isValidAccountId(Account.Type accountType, String accountUniqueID) {
		if (accountType == Account.Type.PHONE) {
			return isValidPhoneNumber(accountUniqueID);
		} else if (accountType == Account.Type.EMAIL) {
			return isValidEmailAddress(accountUniqueID);
		} else {
			return !StringUtils.isEmpty(accountUniqueID);
		}
	}

	/**
	 * Checks if the given string is a valid phone number. A valid phone number
	 * is one that has a non-zero number of digits in it.
	 *
	 * @param phoneNum Phone number string to check.
	 *
	 * @return True if the given string is a valid phone number, false
	 *         otherwise.
	 */
	public static boolean isValidPhoneNumber(String phoneNum) {
		if (!StringUtils.isBlank(phoneNum)) {
			// Any number of digits is good enough.
			return !phoneNum.replaceAll(NON_DIGITS, "").isEmpty();
		} else {
			return false;
		}
	}

	/**
	 * Checks if the given string is a valid email address.
	 *
	 * @param emailAddress String to check.
	 *
	 * @return True if the given string is a valid email address, false
	 *         otherwise.
	 */
	public static boolean isValidEmailAddress(String emailAddress) {
		return EMAIL_VALIDATOR.isValid(emailAddress);
	}
}
