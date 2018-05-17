/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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
package org.sleuthkit.datamodel;

import java.io.Closeable;
import java.util.Collection;

/**
 * A representation of the blackboard, a place where artifacts and their
 * attributes are posted.
 *
 */
public final class Blackboard implements Closeable {

	private SleuthkitCase caseDb;

	/**
	 * Constructs a representation of the blackboard, a place where artifacts
	 * and their attributes are posted.
	 *
	 * @param casedb The case database.
	 */
	Blackboard(SleuthkitCase casedb) {
		this.caseDb = casedb;
	}

	/**
	 * Posts the artifact. This includes making any events that may be derived
	 * from it, and broadcasting a notification that the artifact is ready for
	 * further analysis.
	 *
	 * @param artifact The artifact to be posted.
	 *
	 * @throws BlackboardException If the blackboard is closed.
	 * @throws TskCoreException    If there is a problem posting the artifact.
	 */
	public synchronized void postArtifact(BlackboardArtifact artifact) throws BlackboardException, TskCoreException {
		if (null == caseDb) {
			throw new BlackboardException("Blackboard has been closed");
		}

		caseDb.getTimelineManager().addArtifactEvents(artifact);
		caseDb.postTSKEvent(new ArtifactPostedEvent(artifact));

	}

	/**
	 * Posts a Collection of artifacts. This includes making any events that may
	 * be derived from them, and broadcasting a notifications that the artifacts
	 * are ready for further analysis.
	 *
	 * @param artifacts The artifacts to be posted.
	 *
	 * @throws BlackboardException If the blackboard is closed.
	 * @throws TskCoreException    If there is a problem posting the artifacts.
	 */
	public synchronized void postArtifacts(Collection<BlackboardArtifact> artifacts) throws BlackboardException, TskCoreException {
		/*
		 * For now this just posts them one by one, but in the future it could
		 * be smatter and use transactions, post a single bulk event, etc.
		 */
		for (BlackboardArtifact artifact : artifacts) {
			postArtifact(artifact);
		}
	}

	/**
	 * Gets an artifact type, creating it if it does not already exist. Use this
	 * method to define custom artifact types.
	 *
	 * @param typeName    The type name of the artifact type.
	 * @param displayName The display name of the artifact type.
	 *
	 * @return A type object representing the artifact type.
	 *
	 * @throws BlackboardException If there is a problem getting or adding the
	 *                             artifact type.
	 */
	public synchronized BlackboardArtifact.Type getOrAddArtifactType(String typeName, String displayName) throws BlackboardException {
		if (null == caseDb) {
			throw new BlackboardException("Blackboard has been closed");
		}
		try {
			return caseDb.addBlackboardArtifactType(typeName, displayName);
		} catch (TskDataException typeExistsEx) {
			try {
				return caseDb.getArtifactType(typeName);
			} catch (TskCoreException ex) {
				throw new BlackboardException("Failed to get or add artifact type", ex);
			}
		} catch (TskCoreException ex) {
			throw new BlackboardException("Failed to get or add artifact type", ex);
		}
	}

	/**
	 * Gets an attribute type, creating it if it does not already exist. Use
	 * this method to define custom attribute types.
	 *
	 * @param typeName    The type name of the attribute type.
	 * @param valueType   The value type of the attribute type.
	 * @param displayName The display name of the attribute type.
	 *
	 * @return A type object representing the attribute type.
	 *
	 * @throws BlackboardException If there is a problem getting or adding the
	 *                             attribute type.
	 */
	public synchronized BlackboardAttribute.Type getOrAddAttributeType(String typeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE valueType, String displayName) throws BlackboardException {
		if (null == caseDb) {
			throw new BlackboardException("Blackboard has been closed");
		}
		try {
			return caseDb.addArtifactAttributeType(typeName, valueType, displayName);
		} catch (TskDataException typeExistsEx) {
			try {
				return caseDb.getAttributeType(typeName);
			} catch (TskCoreException ex) {
				throw new BlackboardException("Failed to get or add attribute type", ex);
			}
		} catch (TskCoreException ex) {
			throw new BlackboardException("Failed to get or add attribute type", ex);
		}
	}

	/**
	 * Closes the blackboard.
	 *
	 */
	@Override
	public synchronized void close() {
		caseDb = null;
	}

	/**
	 * A blackboard exception.
	 */
	public static final class BlackboardException extends Exception {

		private static final long serialVersionUID = 1L;

		/**
		 * Constructs a blackboard exception with the specified message.
		 *
		 * @param message The message.
		 */
		BlackboardException(String message) {
			super(message);
		}

		/**
		 * Constructs a blackboard exception with the specified message and
		 * cause.
		 *
		 * @param message The message.
		 * @param cause   The cause.
		 */
		BlackboardException(String message, Throwable cause) {
			super(message, cause);
		}
	}

	/**
	 * Event published by SleuthkitCase when an artifact is posted. A posted
	 * artifact is complete and ready for further processing.
	 */
	final public static class ArtifactPostedEvent {

		private final BlackboardArtifact artifact;

		public BlackboardArtifact getArtifact() {
			return artifact;
		}

		ArtifactPostedEvent(BlackboardArtifact artifact) {
			this.artifact = artifact;
		}
	}
}
