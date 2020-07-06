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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;

/**
 * Provides general utility methods related to communications artifacts.
 *
 */
public final class CommunicationsUtils {

	// These symbols are allowed in dialed or written forms of phone numbers.
	// A '+' is allowed only as a leading digit and hence not inlcuded here.
	private static final Set<String> TELEPHONY_CHARS = new HashSet<>(Arrays.asList(
			"-", "(", ")", "#", "*", ","
	));

	/**
	 * Empty private constructor.
	 */
	private CommunicationsUtils() {
	}

	/**
	 * Normalize the given phone number by removing all non numeric characters,
	 * except: a leading + # or * or ,
	 *
	 * Note: this method intentionally performs a rather lenient validation of
	 * the phone number in order to not drop any collected data.
	 *
	 * @param phoneNumber The string to normalize.
	 *
	 * @return The normalized phone number.
	 *
	 * @throws InvalidAccountIDException If the given string is not a valid
	 *                                   phone number.
	 *
	 */
	public static String normalizePhoneNum(String phoneNumber) throws InvalidAccountIDException {

		if (StringUtils.isEmpty(phoneNumber)) {
			throw new InvalidAccountIDException("Input phone number is null or empty.");
		}

		String normalizedNumber = phoneNumber.trim();

		// A phone number may have a leading '+', special telephony chars, or digits.
		// Anything else implies an invalid phone number.
		for (int i = 0; i < phoneNumber.length(); i++) {
			if ((i == 0 && phoneNumber.charAt(i) == '+')
					|| Character.isSpaceChar(phoneNumber.charAt(i))
					|| Character.isDigit(phoneNumber.charAt(i))
					|| TELEPHONY_CHARS.contains(String.valueOf(phoneNumber.charAt(i)))) {
				// continue
			} else {
				throw new InvalidAccountIDException("Invalid phone number string " + phoneNumber);
			}
		}

		normalizedNumber = normalizedNumber.replaceAll("\\s+", ""); // remove spaces.	
		normalizedNumber = normalizedNumber.replaceAll("[\\-()]", ""); // remove parens & dashes.

		// ensure a min length
		if (normalizedNumber.length() < 3) {
			throw new InvalidAccountIDException("Invalid phone number string " + phoneNumber);

		}
		return normalizedNumber;
	}

	/**
	 * Normalizes the given email address.
	 *
	 * @param emailAddress The email address string to be normalized.
	 *
	 * @return The normalized email address.
	 *
	 * @throws InvalidAccountIDException If the given string is not a valid
	 *                                   email address.
	 */
	public static String normalizeEmailAddress(String emailAddress) throws InvalidAccountIDException {

		if (StringUtils.isEmpty(emailAddress)) {
			throw new InvalidAccountIDException(String.format("Input email address is empty or null."));
		}

		if (isValidEmailAddress(emailAddress) == false) {
			throw new InvalidAccountIDException(String.format("Input string is not a valid email address: %s", emailAddress));
		}

		return emailAddress.toLowerCase().trim();
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
		}
		if (accountType == Account.Type.EMAIL) {
			return isValidEmailAddress(accountUniqueID);
		}

		return !StringUtils.isEmpty(accountUniqueID);
	}

	/**
	 * Checks if the given string is a valid phone number.
	 *
	 * NOTE: this method intentionally performs a rather lenient validation of
	 * the phone number in order to not drop any collected data.
	 *
	 * @param phoneNum Phone number string to check.
	 *
	 * @return True if the given string is a valid phone number, false
	 *         otherwise.
	 */
	public static boolean isValidPhoneNumber(String phoneNum) {
		if (StringUtils.isEmpty(phoneNum)) {
			return false;
		}

		// short min length allows of dial codes.
		if (phoneNum.length() < 3) {
			return false;
		}

		// A phone number may have a leading '+', special telephony chars, or digits.
		// Anything else implies an invalid phone number.
		for (int i = 0; i < phoneNum.length(); i++) {
			if ((i == 0 && phoneNum.charAt(i) == '+')
					|| Character.isSpaceChar(phoneNum.charAt(i))
					|| Character.isDigit(phoneNum.charAt(i))
					|| TELEPHONY_CHARS.contains(String.valueOf(phoneNum.charAt(i)))) {
				// continue
			} else {
				return false;
			}
		}

		return true;
	}

	/**
	 * Checks if the given string is a valid email address.
	 *
	 * Note: this method intentionally performs a rather lenient validation in
	 * order to not drop any collected data.
	 *
	 * Note: We are requiring that an email address have a "." on the right-hand
	 * side to allow us to differentiate between app-specific identifiers and
	 * email addresses. We realize that some emails can be sent within
	 * enterprises without a ".', but that this is less common than encountering
	 * app-specific identifiers of the form a@b.
	 *
	 * @param emailAddress String to check.
	 *
	 * @return True if the given string is a valid email address, false
	 *         otherwise.
	 */
	public static boolean isValidEmailAddress(String emailAddress) {
		if (StringUtils.isEmpty(emailAddress)) {
			return false;
		}

		if (emailAddress.contains("@") == false
				|| emailAddress.contains(".") == false
				|| emailAddress.length() < 5) {
			return false;
		}

		// emsure there's a username and domain 
		String[] tokens = emailAddress.split("@");
		if (tokens.length < 2
				|| StringUtils.isEmpty(tokens[0])
				|| StringUtils.isEmpty(tokens[1])) {
			return false;
		}

		// ensure domain has name and suffix
		String[] tokens2 = tokens[1].split("\\.");
		if (tokens2.length < 2
				|| StringUtils.isEmpty(tokens2[0])
				|| StringUtils.isEmpty(tokens2[1])) {
			return false;
		}

		return true;
	}
}
