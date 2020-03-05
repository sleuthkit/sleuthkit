/*
 * Sleuth Kit Data Model
 *
 * Copyright 2019-2020 Basis Technology Corp.
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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.StringTokenizer;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.Account;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.CommunicationsManager;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Class to help ingest modules create Web Browser artifacts.
 *
 * These include bookmarks, cookies, downloads, history, and web form
 * autofill data.
 *
 */
public final class WebBrowserArtifactsHelper extends ArtifactHelperBase {

	/**
	 * Creates a WebBrowserArtifactsHelper.
	 *
	 * @param caseDb     Sleuthkit case db.
	 * @param moduleName Name of module using the helper.
	 * @param srcContent Source content being processed by the module.
	 *
	 */
	public WebBrowserArtifactsHelper(SleuthkitCase caseDb, String moduleName, Content srcContent) {
		super(caseDb, moduleName, srcContent);
	}

	/**
	 * Adds a TSK_WEB_BOOKMARK artifact.
	 *
	 * @param url          Bookmark URL, required.
	 * @param title        Bookmark title, may be empty/null.
	 * @param creationTime Date/time created, may be 0 if not available.
	 * @param progName     Application/program that created bookmark, may be
	 *                     empty/null.
	 *
	 * @return Bookmark artifact.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebBookmark(String url, String title, long creationTime, String progName) throws TskCoreException, BlackboardException {
		return addWebBookmark(url, title, creationTime, progName,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_WEB_BOOKMARK artifact.
	 *
	 * @param url                 Bookmark URL, required.
	 * @param title               Bookmark title, may be empty/null.
	 * @param creationTime        Date/time created, may be 0 if not available.
	 * @param progName            Application/program that created bookmark, may
	 *                            be empty/null.
	 * @param otherAttributesList Other attributes, may be an empty list.
	 *
	 * @return Bookmark artifact.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebBookmark(String url, String title, long creationTime, String progName,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		BlackboardArtifact bookMarkArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create artifact
		bookMarkArtifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_BOOKMARK);

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, getModuleName(), url));

		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, creationTime, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE, title, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, extractDomain(url), attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, progName, attributes);

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		bookMarkArtifact.addAttributes(attributes);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(bookMarkArtifact, getModuleName());

		// return the artifact
		return bookMarkArtifact;
	}

	/**
	 * Adds a TSK_WEB_COOKIE artifact.
	 *
	 * @param url          Url of the site that created the cookie, required.
	 * @param creationTime Create time of cookie, may be 0 if not available.
	 * @param name         Cookie name, may be empty or null.
	 * @param value        Cookie value, may be empty or null.
	 * @param programName  Name of the application/program that created the
	 *                     cookie, may be empty or null.
	 *
	 * @return WebCookie artifact
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebCookie(String url, long creationTime,
			String name, String value, String programName) throws TskCoreException, BlackboardException {

		return addWebCookie(url, creationTime, name, value, programName,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_WEB_COOKIE artifact.
	 *
	 * @param url                 Url of the site that created the cookie,
	 *                            required.
	 * @param creationTime        Create time of cookie, may be 0 if not
	 *                            available.
	 * @param name                Cookie name, may be empty or null.
	 * @param value               Cookie value, may be empty or null.
	 * @param programName         Name of the application/program that created
	 *                            the cookie, may be empty or null.
	 *
	 * @param otherAttributesList Other attributes, may be an empty list.
	 *
	 * @return WebCookie artifact
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebCookie(String url,
			long creationTime, String name, String value, String programName,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		BlackboardArtifact cookieArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create artifact
		cookieArtifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE);

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, getModuleName(), url));

		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, creationTime, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, name, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, value, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, extractDomain(url), attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, programName, attributes);

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		cookieArtifact.addAttributes(attributes);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(cookieArtifact, getModuleName());

		// return the artifact
		return cookieArtifact;
	}

	/**
	 * Adds a TSK_WEB_DOWNNLOAD artifact.
	 *
	 * @param url         URL downloaded from, required.
	 * @param startTime   Date/time downloaded, 0 if not available.
	 * @param path        Path of downloaded file, required.
	 * @param programName Program that initiated the download, may be empty or
	 *                    null.
	 *
	 * @return Web download artifact created.
	 *
	 * @throws TskCoreException    If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebDownload(String url, long startTime, String path, String programName) throws TskCoreException, BlackboardException {
		return addWebDownload(path, startTime, url, programName, Collections.emptyList());
	}

	/**
	 * Adds a TSK_WEB_DOWNNLOAD artifact.
	 *
	 * @param url                 URL downloaded from, required.
	 * @param startTime           Date/time downloaded, 0 if not available.
	 * @param path                Path of downloaded file, required.
	 * @param programName         Program that initiated the download, may be
	 *                            empty or null.
	 * @param otherAttributesList Other attributes, may be an empty list.
	 *
	 * @return Web download artifact created.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebDownload(String url, long startTime, String path, String programName,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		BlackboardArtifact webDownloadArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// reate artifact
		webDownloadArtifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD);

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH, getModuleName(), path));
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, getModuleName(), url));

		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, startTime, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, programName, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, extractDomain(url), attributes);

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		webDownloadArtifact.addAttributes(attributes);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(webDownloadArtifact, getModuleName());

		// return the artifact
		return webDownloadArtifact;
	}

	/**
	 * Adds a TSK_WEB_FORM_AUTOFILL artifact.
	 *
	 * @param personName     Person name, required.
	 * @param email          Email address, may be empty or null.
	 * @param phoneNumber    Phone number, may be empty or null.
	 * @param mailingAddress Mailing address, may be empty or null.
	 * @param creationTime   Creation time, may be 0 if not available.
	 * @param accessTime     Last access time, may be 0 if not available.
	 * @param count          Use count, may be 0 if not available.
	 *
	 * @return Web form address artifact created.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebFormAddress(String personName, String email,
			String phoneNumber, String mailingAddress,
			long creationTime, long accessTime, int count) throws TskCoreException, BlackboardException {
		return addWebFormAddress(personName, email, phoneNumber,
				mailingAddress, creationTime, accessTime, count,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_WEB_FORM_ADDRESS artifact.
	 *
	 * @param personName          Person name, required.
	 * @param email               Email address, may be empty or null.
	 * @param phoneNumber         Phone number, may be empty or null.
	 * @param mailingAddress      Mailing address, may be empty or null.
	 * @param creationTime        Creation time, may be 0 if not available.
	 * @param accessTime          Last access time, may be 0 if not available.
	 * @param count               Use count, may be 0 if not available.
	 * @param otherAttributesList Other attributes, may be an empty list.
	 *
	 * @return Web form address artifact created.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebFormAddress(String personName, String email,
			String phoneNumber, String mailingAddress,
			long creationTime, long accessTime, int count,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		BlackboardArtifact webFormAddressArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();
		
		CommunicationsManager commManager = this.getSleuthkitCase().getCommunicationsManager();
		if(StringUtils.isNotBlank(email)) {
			commManager.createAccountFileInstance(Account.Type.EMAIL, email, this.getModuleName(), this.getContent());
		}

		if(StringUtils.isNotBlank(phoneNumber)) {
			commManager.createAccountFileInstance(Account.Type.PHONE, phoneNumber, this.getModuleName(), this.getContent());
		}

		// create artifact
		webFormAddressArtifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_FORM_ADDRESS);

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), personName));

		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL, email, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, phoneNumber, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCATION, mailingAddress, attributes);

		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, creationTime, attributes);
		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, accessTime, attributes);
		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNT, count, attributes);

		// add artifact
		attributes.addAll(otherAttributesList);
		webFormAddressArtifact.addAttributes(attributes);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(webFormAddressArtifact, getModuleName());

		// return the artifact
		return webFormAddressArtifact;
	}

	/**
	 * Adds a TSK_WEB_FORM_AUTOFILL artifact.
	 *
	 * @param name         Name of autofill field, required.
	 * @param value        Value of autofill field, required.
	 * @param creationTime Create date/time, may be 0 if not available.
	 * @param accessTime   Last access date/time, may be 0 if not available.
	 * @param count        Count of times used, may be 0 if not available.
	 *
	 * @return Web form autofill artifact created.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebFormAutofill(String name, String value,
			long creationTime, long accessTime, int count) throws TskCoreException, BlackboardException {
		return addWebFormAutofill(name, value, creationTime, accessTime, count,
				Collections.emptyList());
	}

	/**
	 * Adds a TSK_WEB_FORM_AUTOFILL artifact.
	 *
	 * @param name                Name of autofill field, required.
	 * @param value               Value of autofill field, required.
	 * @param creationTime        Create date/time, may be 0 if not available.
	 * @param accessTime          Last access date/time, may be 0 if not
	 *                            available.
	 * @param count               Count of times used, may be 0 if not
	 *                            available.
	 * @param otherAttributesList Other attributes, may be an empty list.
	 *
	 * @return Web form autofill artifact created.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebFormAutofill(String name, String value,
			long creationTime, long accessTime, int count,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {
		BlackboardArtifact webFormAutofillArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create artifact
		webFormAutofillArtifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_FORM_AUTOFILL);

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), name));
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, getModuleName(), value));

		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, creationTime, attributes);
		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, accessTime, attributes);
		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNT, count, attributes);

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		webFormAutofillArtifact.addAttributes(attributes);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(webFormAutofillArtifact, getModuleName());

		// return the artifact
		return webFormAutofillArtifact;
	}

	/**
	 * Adds a Web History artifact.
	 *
	 * @param url          Url visited, required.
	 * @param accessTime   Last access time, may be 0 if not available.
	 * @param referrer     Referrer, may be empty or null.
	 * @param title        Website title, may be empty or null.
	 * @param programName  Application/program recording the history, may be
	 *                     empty or null.
	 *
	 * @return Web history artifact created.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebHistory(String url, long accessTime,
			String referrer, String title, String programName) throws TskCoreException, BlackboardException {
		return addWebHistory(url, accessTime, referrer, title, programName,
				Collections.emptyList());
	}

	/**
	 * Adds a Web History artifact.
	 *
	 * @param url                 Url visited, required.
	 * @param accessTime          Last access time, may be 0 if not available.
	 * @param referrer            Referrer, may be empty or null.
	 * @param title               Website title, may be empty or null.
	 * @param programName         Application/program recording the history, may
	 *                            be empty or null.
	 * @param otherAttributesList Other attributes, may be an empty list.
	 *
	 * @return Web history artifact created.
	 *
	 * @throws TskCoreException	   If there is an error creating the artifact.
	 * @throws BlackboardException If there is a problem posting the artifact.
	 */
	public BlackboardArtifact addWebHistory(String url, long accessTime,
			String referrer, String title, String programName,
			Collection<BlackboardAttribute> otherAttributesList) throws TskCoreException, BlackboardException {

		BlackboardArtifact webHistoryArtifact;
		Collection<BlackboardAttribute> attributes = new ArrayList<>();

		// create artifact
		webHistoryArtifact = getContent().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY);

		// construct attributes 
		attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, getModuleName(), url));

		addAttributeIfNotZero(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, accessTime, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE, title, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_REFERRER, referrer, attributes);

		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, programName, attributes);
		addAttributeIfNotNull(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, extractDomain(url), attributes);

		// add attributes to artifact
		attributes.addAll(otherAttributesList);
		webHistoryArtifact.addAttributes(attributes);

		// post artifact 
		getSleuthkitCase().getBlackboard().postArtifact(webHistoryArtifact, getModuleName());

		// return the artifact
		return webHistoryArtifact;
	}

	// TBD: this is duplicated in Autopsy. 
	// We should move this to new Util class in TSK, and have Autopsy delegate to it.
	/**
	 * Attempt to extract the domain from a URL. Will start by using the
	 * built-in URL class, and if that fails will try to extract it manually.
	 *
	 * @param urlString The URL to extract the domain from
	 *
	 * @return empty string if no domain name was found
	 */
	private static String extractDomain(String urlString) {
		if (urlString == null) {
			return "";
		}
		String result;

		try {
			URL url = new URL(urlString);
			result = url.getHost();
		} catch (MalformedURLException ex) {
			// not a valid URL - we will try to extract it ourselves
			result = null;
		}

		//was not a valid URL, try a less picky method
		if (result == null || StringUtils.isBlank(result)) {
			return getBaseDomain(urlString);
		}
		return result;
	}

	/**
	 * Attempt to manually extract the domain from a URL.
	 *
	 * @param url
	 *
	 * @return empty string if no domain could be found
	 */
	private static String getBaseDomain(String url) {
		String host;

		//strip protocol
		String cleanUrl = url.replaceFirst(".*:\\/\\/", "");

		//strip after slashes
		String dirToks[] = cleanUrl.split("\\/");
		if (dirToks.length > 0) {
			host = dirToks[0];
		} else {
			host = cleanUrl;
		}

		//get the domain part from host (last 2)
		StringTokenizer tok = new StringTokenizer(host, ".");
		StringBuilder hostB = new StringBuilder();
		int toks = tok.countTokens();

		for (int count = 0; count < toks; ++count) {
			String part = tok.nextToken();
			int diff = toks - count;
			if (diff < 3) {
				hostB.append(part);
			}
			if (diff == 2) {
				hostB.append('.');
			}
		}

		String base = hostB.toString();
		// verify there are no special characters in there
		if (base.matches(".*[~`!@#$%^&\\*\\(\\)\\+={}\\[\\];:\\?<>,/ ].*")) {
			return "";
		}

		//verify that the base domain actually has a '.', details JIRA-4609
		if (!base.contains(".")) {
			return "";
		}

		return base;
	}
}
