/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2017 Basis Technology Corp.
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

/**
 * Instance of an account. A account may be extracted from multiple sources, one
 * per Content, each represents an instance of the account. There is a 1:N
 * relationships between Account & AccountInstance
 *
 * Account instances are stored as Artifacts for type TSK_ACCOUNT
 */
public class AccountInstance {

	private final SleuthkitCase sleuthkitCase;
	private final long artifactId;	// ArtifactID of the underlying TSK_ACCOUNT artifact - that represents an instance 
	private final BlackboardArtifact artifact;
	private final long account_id;	// id f corresponding account.

	AccountInstance(SleuthkitCase sleuthkitCase, long artifactId, long account_id) throws TskCoreException {

		this.sleuthkitCase = sleuthkitCase;
		this.artifactId = artifactId;
		this.account_id = account_id;
		this.artifact = sleuthkitCase.getBlackboardArtifact(artifactId);
	}

	AccountInstance(SleuthkitCase sleuthkitCase, BlackboardArtifact artifact, Account account) throws TskCoreException {
		this.sleuthkitCase = sleuthkitCase;
		this.artifact = artifact;
		this.artifactId = artifact.getArtifactID();
		this.account_id = account.getAccountId();
	}

	public BlackboardAttribute getAttribute(BlackboardAttribute.ATTRIBUTE_TYPE attrType) throws TskCoreException {
		return this.artifact.getAttribute(new BlackboardAttribute.Type(attrType));
	}

	public void addAttribute(BlackboardAttribute bbatr) throws TskCoreException {
		this.artifact.addAttribute(bbatr);
	}

	public long getArtifactId() {
		return this.artifactId;
	}

	public Account getAccount() throws TskCoreException, Exception {
		return this.sleuthkitCase.getCommunicationsManager().getAccount(account_id);
	}

	public long getAccountId() {
		return this.account_id;
	}

	/**
	 * Reject the account instance
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public void rejectAccount() throws TskCoreException {
		this.sleuthkitCase.setReviewStatus(this.sleuthkitCase.getBlackboardArtifact(this.getArtifactId()), BlackboardArtifact.ReviewStatus.REJECTED);
	}

	/**
	 * Reject the account instance
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public void approveAccount() throws TskCoreException {
		this.sleuthkitCase.setReviewStatus(this.sleuthkitCase.getBlackboardArtifact(this.getArtifactId()), BlackboardArtifact.ReviewStatus.APPROVED);
	}

	/**
	 * Set review status for the account instance
	 *
	 * @param reviewStatus
	 *
	 * @throws TskCoreException exception thrown if a critical error occurs
	 */
	public void setReviewStatus(BlackboardArtifact.ReviewStatus reviewStatus) throws TskCoreException {
		this.sleuthkitCase.setReviewStatus(this.sleuthkitCase.getBlackboardArtifact(this.getArtifactId()), reviewStatus);
	}

}
