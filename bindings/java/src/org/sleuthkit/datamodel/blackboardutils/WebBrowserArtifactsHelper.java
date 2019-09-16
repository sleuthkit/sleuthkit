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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Class to help ingest modules create Web Browser artifacts.
 *
 */
public final class WebBrowserArtifactsHelper extends AbstractArtifactHelper {

	private static final Logger logger = Logger.getLogger(ArtifactsHelper.class.getName());

	/**
	 * Creates an WebBrowserArtifactsHelper.
	 *
	 * @param caseDb     Sleuthkit case db
	 * @param moduleName name module using the helper
	 * @param srcFile    source file
	 *
	 */
	public WebBrowserArtifactsHelper(SleuthkitCase caseDb, String moduleName, AbstractFile srcFile) {
		super(caseDb, moduleName, srcFile);
	}

	/**
	 * Adds a TSK_WEB_BOOKMARK artifact.
	 *
	 * @param url          bookmark URL, required
	 * @param title        bookmark title, may be empty/null
	 * @param creationTime date/time created, may be 0 if not available
	 * @param progName     application/program that created bookmark, may be
	 *                     empty/null
	 *
	 * @return bookmark artifact
	 */
	public BlackboardArtifact addWebBookmark(String url, String title, long creationTime, String progName) {
		return addWebBookmark(url, title, creationTime, progName,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a TSK_WEB_BOOKMARK artifact.
	 *
	 * @param url                 bookmark URL, required
	 * @param title               bookmark title, may be empty/null
	 * @param creationTime        date/time created, may be 0 if not available
	 * @param progName            application/program that created bookmark, may
	 *                            be empty/null
	 * @param otherAttributesList other attributes, may be an empty list
	 *
	 * @return bookmark artifact
	 */
	public BlackboardArtifact addWebBookmark(String url, String title, long creationTime, String progName,
			Collection<BlackboardAttribute> otherAttributesList) {

		BlackboardArtifact bookMarkArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();

			// Create artifact
			bookMarkArtifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_BOOKMARK);

			// Add basic attributes 
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, getModuleName(), url));
			if (creationTime > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, getModuleName(), creationTime));
			}

			if (!StringUtils.isEmpty(title)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE, getModuleName(), title));
			}
			if (!StringUtils.isEmpty(url)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, getModuleName(), extractDomain(url)));
			}
			if (!StringUtils.isEmpty(progName)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), progName));
			}

			// Add  attributes to artifact
			bookMarkArtifact.addAttributes(attributes);
			bookMarkArtifact.addAttributes(otherAttributesList);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(bookMarkArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add bookmark artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((bookMarkArtifact != null) ? bookMarkArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		// return the artifact
		return bookMarkArtifact;
	}

	/**
	 * Adds a TSK_WEB_COOKIE artifact
	 *
	 * @param url          url of the site that created the cookie, required
	 * @param creationTime create time of cookie, may be 0 if not available
	 * @param name         cookie name, may be empty or null
	 * @param value        cookie value, may be empty or null
	 * @param programName  name of the application that created the cookie, may
	 *                     be empty or null
	 *
	 * @return WebCookie artifact
	 */
	public BlackboardArtifact addWebCookie(String url, long creationTime,
			String name, String value, String programName) {

		return addWebCookie(url, creationTime, name, value, programName,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a TSK_WEB_COOKIE artifact
	 *
	 * @param url                 url of the site that created the cookie,
	 *                            required
	 * @param creationTime        create time of cookie, may be 0 if not
	 *                            available
	 * @param name                cookie name, may be empty or null
	 * @param value               cookie value, may be empty or null
	 * @param programName         name of the application that created the
	 *                            cookie, may be empty or null
	 *
	 * @param otherAttributesList other attributes, may be an empty list
	 *
	 * @return WebCookie artifact
	 */
	public BlackboardArtifact addWebCookie(String url,
			long creationTime, String name, String value, String programName,
			Collection<BlackboardAttribute> otherAttributesList) {

		BlackboardArtifact cookieArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();

			// Create artifact
			cookieArtifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_COOKIE);

			// Add basic attributes 
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, getModuleName(), url));
			if (creationTime > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, getModuleName(), creationTime));
			}

			if (!StringUtils.isEmpty(name)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), name));
			}
			if (!StringUtils.isEmpty(value)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, getModuleName(), value));
			}
			if (!StringUtils.isEmpty(url)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, getModuleName(), extractDomain(url)));
			}
			if (!StringUtils.isEmpty(programName)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
			}

			cookieArtifact.addAttributes(attributes);
			cookieArtifact.addAttributes(otherAttributesList);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(cookieArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add bookmark artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((cookieArtifact != null) ? cookieArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		// return the artifact
		return cookieArtifact;
	}

	/**
	 * Created a TSK_WEB_DOWNNLOAD artifact
	 *
	 * @param path        path of downloaded file, required
	 * @param startTime   date/time downloaded, 0 if not available
	 * @param url         URL downloaded from, required
	 * @param programName program that initiated download, may be empty or null
	 *
	 *
	 * @return artifact created
	 */
	public BlackboardArtifact addWebDownload(String path, long startTime, String url, String programName) {
		return addWebDownload(path, startTime, url, programName, Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Created a TSK_WEB_DOWNNLOAD artifact
	 *
	 * @param path                path of downloaded file, required
	 * @param startTime           date/time downloaded, 0 if not available
	 * @param url                 URL downloaded from, required
	 * @param programName         program that initiated download, may be empty
	 *                            or null
	 * @param otherAttributesList other attributes, may be an empty list
	 *
	 *
	 * @return artifact created
	 */
	public BlackboardArtifact addWebDownload(String path, long startTime, String url, String programName,
			Collection<BlackboardAttribute> otherAttributesList) {

		BlackboardArtifact webDownloadArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();

			// Create artifact
			webDownloadArtifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD);

			// Add basic attributes 
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH, getModuleName(), path));
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, getModuleName(), url));
			if (startTime > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, getModuleName(), startTime));
			}

			if (!StringUtils.isEmpty(programName)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
			}
			if (!StringUtils.isEmpty(url)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, getModuleName(), extractDomain(url)));
			}

			webDownloadArtifact.addAttributes(attributes);
			webDownloadArtifact.addAttributes(otherAttributesList);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(webDownloadArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add web download artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((webDownloadArtifact != null) ? webDownloadArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		// return the artifact
		return webDownloadArtifact;
	}

	/**
	 * Adds a TSK_WEB_FORM_AUTOFILL artifact.
	 *
	 * @param personName     person name, required
	 * @param email          email address, may be empty or null
	 * @param phoneNumber    phone number, may be empty or null
	 * @param mailingAddress mailing address, may be empty or null
	 * @param creationTime   creation time, may be 0 if not available
	 * @param accessTime     last access time, may be 0 if not available
	 * @param count          use count, may be 0 if not available
	 *
	 * @return artifact created
	 */
	public BlackboardArtifact addWebFormAddress(String personName, String email,
			String phoneNumber, String mailingAddress,
			long creationTime, long accessTime, int count) {
		return addWebFormAddress(personName, email, phoneNumber,
				mailingAddress, creationTime, accessTime, count,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a TSK_WEB_FORM_ADDRESS artifact.
	 *
	 * @param personName          person name, required
	 * @param email               email address, may be empty or null
	 * @param phoneNumber         phone number, may be empty or null
	 * @param mailingAddress      mailing address, may be empty or null
	 * @param creationTime        creation time, may be 0 if not available
	 * @param accessTime          last access time, may be 0 if not available
	 * @param count               use count, may be 0 if not available
	 * @param otherAttributesList other attributes, may be an empty list
	 *
	 * @return artifact created
	 */
	public BlackboardArtifact addWebFormAddress(String personName, String email,
			String phoneNumber, String mailingAddress,
			long creationTime, long accessTime, int count,
			Collection<BlackboardAttribute> otherAttributesList) {

		BlackboardArtifact webFormAddressArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();

			// Create artifact
			webFormAddressArtifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_FORM_ADDRESS);

			// Add basic attributes 
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), personName));

			if (!StringUtils.isEmpty(email)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL, getModuleName(), email));
			}
			if (!StringUtils.isEmpty(phoneNumber)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, getModuleName(), phoneNumber));
			}
			if (!StringUtils.isEmpty(mailingAddress)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCATION, getModuleName(), mailingAddress));
			}

			if (creationTime > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, getModuleName(), creationTime));
			}
			if (accessTime > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, getModuleName(), accessTime));
			}
			if (count > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNT, getModuleName(), count));
			}

			webFormAddressArtifact.addAttributes(attributes);
			webFormAddressArtifact.addAttributes(otherAttributesList);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(webFormAddressArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add web form address artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((webFormAddressArtifact != null) ? webFormAddressArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		// return the artifact
		return webFormAddressArtifact;
	}

	/**
	 * Adds a TSK_WEB_FORM_AUTOFILL artifact
	 *
	 * @param name         name of autofill field, required
	 * @param value        value of autofill field, required
	 * @param creationTime create date/time, may be 0 if not available
	 * @param accessTime   last access date/time, may be 0 if not available
	 * @param count        count of times used, may be 0 if not available
	 *
	 * @return artifact created
	 */
	public BlackboardArtifact addWebFormAutofill(String name, String value,
			long creationTime, long accessTime, int count) {
		return addWebFormAutofill(name, value, creationTime, accessTime, count,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a TSK_WEB_FORM_AUTOFILL artifact.
	 *
	 * @param name                name of autofill field, required
	 * @param value               value of autofill field, required
	 * @param creationTime        create date/time, may be 0 if not available
	 * @param accessTime          last access date/time, may be 0 if not
	 *                            available
	 * @param count               count of times used, may be 0 if not available
	 * @param otherAttributesList additional attributes, may be an empty list
	 *
	 * @return artifact created
	 */
	public BlackboardArtifact addWebFormAutofill(String name, String value,
			long creationTime, long accessTime, int count,
			Collection<BlackboardAttribute> otherAttributesList) {
		BlackboardArtifact webFormAutofillArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();

			// Create artifact
			webFormAutofillArtifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_FORM_AUTOFILL);

			// Add basic attributes 
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), name));
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE, getModuleName(), value));
			if (creationTime > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_CREATED, getModuleName(), creationTime));
			}
			if (accessTime > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, getModuleName(), accessTime));
			}
			if (count > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_COUNT, getModuleName(), count));
			}

			webFormAutofillArtifact.addAttributes(attributes);
			webFormAutofillArtifact.addAttributes(otherAttributesList);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(webFormAutofillArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add web form autofill artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((webFormAutofillArtifact != null) ? webFormAutofillArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		// return the artifact
		return webFormAutofillArtifact;
	}

	/**
	 * Adds a Web History artifact
	 *
	 * @param url          url visited, required
	 * @param accessTime   last access time, may be 0 if not available
	 * @param referrer     referrer, may be empty or null
	 * @param title        website title, may be empty or null
	 * @param programName, application recording the history, may be empty or
	 *                     null
	 *
	 * @return artifact created
	 */
	public BlackboardArtifact addWebHistory(String url, long accessTime,
			String referrer, String title, String programName) {
		return addWebHistory(url, accessTime, referrer, title, programName,
				Collections.<BlackboardAttribute>emptyList());
	}

	/**
	 * Adds a Web History artifact
	 *
	 * @param url                 url visited, required
	 * @param accessTime          last access time, may be 0 if not available
	 * @param referrer            referrer, may be empty or null
	 * @param title               website title, may be empty or null
	 * @param programName,        application recording the history, may be
	 *                            empty or null
	 * @param otherAttributesList other attributes, may be an empty list
	 *
	 * @return artifact created
	 */
	public BlackboardArtifact addWebHistory(String url, long accessTime,
			String referrer, String title, String programName,
			Collection<BlackboardAttribute> otherAttributesList) {

		BlackboardArtifact webHistoryArtifact = null;
		try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();
			// Create artifact
			webHistoryArtifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY);

			// Add basic attributes 
			attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, getModuleName(), url));
			if (accessTime > 0) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED, getModuleName(), accessTime));
			}

			if (!StringUtils.isEmpty(title)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE, getModuleName(), title));
			}
			if (!StringUtils.isEmpty(referrer)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_REFERRER, getModuleName(), referrer));
			}

			if (!StringUtils.isEmpty(programName)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
			}
			if (!StringUtils.isEmpty(url)) {
				attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN, getModuleName(), extractDomain(url)));
			}

			webHistoryArtifact.addAttributes(attributes);
			webHistoryArtifact.addAttributes(otherAttributesList);

			// post artifact 
			getSleuthkitCase().getBlackboard().postArtifact(webHistoryArtifact, getModuleName());
		} catch (TskCoreException ex) {
			logger.log(Level.SEVERE, "Unable to add bookmark artifact", ex); //NON-NLS
			return null;
		} catch (Blackboard.BlackboardException ex) {
			logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((webHistoryArtifact != null) ? webHistoryArtifact.getArtifactID() : "")), ex);  //NON-NLS
		}

		// return the artifact
		return webHistoryArtifact;
	}

	// TBD: this is duplicated in Autopsy/NetworkUtils
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
		String result = "";

		try {
			URL url = new URL(urlString);
			result = url.getHost();
		} catch (MalformedURLException ex) {
			//do not log if not a valid URL - we will try to extract it ourselves
		}

		//was not a valid URL, try a less picky method
		if (result == null || result.trim().isEmpty()) {
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
		String host = null;

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
				hostB.append(".");
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
