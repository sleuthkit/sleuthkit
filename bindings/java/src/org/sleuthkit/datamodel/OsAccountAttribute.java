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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import org.sleuthkit.datamodel.BlackboardAttribute.Type;

/**
 * Abstracts host specific attributes of an OS account. As an example, last
 * login on a specific host.
 *
 */
public final class OsAccountAttribute extends AbstractAttribute {

	private final long osAccountId;	// OS account to which this attribute belongs.
	private final long hostId; // Host to which this attribute applies.
	private final long sourceObjId; // Object id of the source where the attribute was discoevered.

	/**
	 * Creates an os account attribute with int value.
	 *
	 * @param attributeType Attribute type.
	 * @param valueInt	    Int value.
	 * @param osAccountId	Id of account which the attribute pertains to.
	 * @param sourceObjId   Object id of the source where the attribute was
	 *                      found.
	 * @param hostId        Host on which the attribute applies to.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, int valueInt, long osAccountId, long hostId, long sourceObjId) {
		super(attributeType, valueInt);

		this.osAccountId = osAccountId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Creates an os account attribute with long value.
	 *
	 * @param attributeType Attribute type.
	 * @param valueLong	    Long value.
	 * @param osAccountId   Id of account which the attribute pertains to.
	 * @param sourceObjId   Object id of the source where the attribute was
	 *                      found.
	 * @param hostId        Host on which the attribute applies to.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, long valueLong, long osAccountId, long hostId, long sourceObjId) {
		super(attributeType, valueLong);

		this.osAccountId = osAccountId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Creates an os account attribute with double value.
	 *
	 * @param attributeType Attribute type.
	 * @param valueDouble   Double value.
	 * @param osAccountId   Id of account which the attribute pertains to.
	 * @param sourceObjId   Object id of the source where the attribute was
	 *                      found.
	 * @param hostId        Host on which the attribute applies to.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, double valueDouble, long osAccountId, long hostId, long sourceObjId) {
		super(attributeType, valueDouble);

		this.osAccountId = osAccountId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Creates an os account attribute with string value.
	 *
	 * @param attributeType  Attribute type.
	 * @param valueString    String value.
	 * @param osAccountId	 Id of account which the attribute pertains to.
	 * @param sourceObjId    Object id of the source where the attribute was
	 *                       found.
	 * @param hostId         Host on which the attribute applies to.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, String valueString, long osAccountId, long hostId, long sourceObjId) {
		super(attributeType, valueString);

		this.osAccountId = osAccountId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Creates an os account attribute with byte-array value.
	 *
	 * @param attributeType Attribute type.
	 * @param valueBytes    Bytes value.
	 * @param osAccountId   Id of account which the attribute pertains to.
	 * @param sourceObjId   Object id of the source where the attribute was
	 *                      found.
	 * @param hostId        Host on which the attribute applies to.
	 */
	public OsAccountAttribute(Type attributeType, byte[] valueBytes, long osAccountId, long hostId, long sourceObjId) {
		super(attributeType, valueBytes);

		this.osAccountId = osAccountId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Constructor to be used when creating an attribute after reading the data
	 * from the table.
	 *
	 * @param attributeType  Attribute type.
	 * @param valueInt       Int value.
	 * @param valueLong      Long value.
	 * @param valueDouble    Double value.
	 * @param valueString    String value.
	 * @param valueBytes     Bytes value.
	 * @param sleuthkitCase  Sleuthkit case.
	 * @param osAccountId    Id of account which the attribute pertains to.
	 * @param sourceObjId    Object id of the source where the attribute was
	 *                       found.
	 * @param hostId         Host on which the attribute applies to.
	 */
	OsAccountAttribute(BlackboardAttribute.Type attributeType, int valueInt, long valueLong, double valueDouble, String valueString, byte[] valueBytes,
			SleuthkitCase sleuthkitCase, long osAccountId, long sourceObjId, long hostId) {

		super(osAccountId, attributeType,
				valueInt, valueLong, valueDouble, valueString, valueBytes,
				sleuthkitCase);
		this.osAccountId = osAccountId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Get the host id for the account attribute.
	 *
	 * @return Host id.
	 */
	long getHostId() {
		return hostId;
	}

	/**
	 * Get the account id of account to which this attribute applies.
	 *
	 * @return Account row id.
	 */
	public long getOsAccountId() {
		return osAccountId;
	}

	/**
	 * Get the object id of the source where the attribute was found.
	 *
	 * @return Object id of source.
	 */
	public long getSourceObjId() {
		return sourceObjId;
	}

}
