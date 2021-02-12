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

import java.util.Optional;
import org.sleuthkit.datamodel.BlackboardAttribute.Type;

/**
 * Abstracts host specific attributes of an OS account. As an example, last
 * login on a specific host.
 *
 */
public final class OsAccountAttribute extends AbstractAttribute {

	private final long osAccountObjId;	// OS account to which this attribute belongs.
	private final Long hostId; // Host to which this attribute applies, may be null
	private final Long sourceObjId; // Object id of the source where the attribute was discovered.

	/**
	 * Creates an os account attribute with int value.
	 *
	 * @param attributeType  Attribute type.
	 * @param valueInt	      Int value.
	 * @param osAccountObjId Obj id of account which the attribute pertains to. 
	 * @param hostId         Id of host on which the attribute applies to. Pass
	 *                       Null if it applies across hosts.
	 * @param sourceObjId    Object id of the source where the attribute was
	 *                       found.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, int valueInt, long osAccountObjId, Long hostId, Long sourceObjId) {
		super(attributeType, valueInt);

		this.osAccountObjId = osAccountObjId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Creates an os account attribute with long value.
	 *
	 * @param attributeType  Attribute type.
	 * @param valueLong	     Long value.
	 * @param osAccountObjId Obj id of account which the attribute pertains to.
	 * @param hostId         Id of host on which the attribute applies to. Pass
	 *                       Null if it applies across hosts.
	 * @param sourceObjId    Object id of the source where the attribute was
	 *                       found.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, long valueLong, long osAccountObjId, Long hostId, Long sourceObjId) {
		super(attributeType, valueLong);

		this.osAccountObjId = osAccountObjId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Creates an os account attribute with double value.
	 *
	 * @param attributeType  Attribute type.
	 * @param valueDouble    Double value.
	 * @param osAccountObjId Obj id of account which the attribute pertains to.
	 * @param hostId         Id of host on which the attribute applies to. Pass
	 *                       Null if it applies across hosts.
	 * @param sourceObjId    Object id of the source where the attribute was
	 *                       found.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, double valueDouble, long osAccountObjId, Long hostId, Long sourceObjId) {
		super(attributeType, valueDouble);

		this.osAccountObjId = osAccountObjId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Creates an os account attribute with string value.
	 *
	 * @param attributeType  Attribute type.
	 * @param valueString    String value.
	 * @param osAccountObjId Obj id of account which the attribute pertains to.
	 * @param hostId         Id of host on which the attribute applies to. Pass
	 *                       Null if it applies across hosts.
	 * @param sourceObjId    Object id of the source where the attribute was
	 *                       found.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, String valueString, long osAccountObjId, Long hostId, Long sourceObjId) {
		super(attributeType, valueString);

		this.osAccountObjId = osAccountObjId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Creates an os account attribute with byte-array value.
	 *
	 * @param attributeType  Attribute type.
	 * @param valueBytes     Bytes value.
	 * @param osAccountObjId Obj id of account which the attribute pertains to.
	 * @param hostId         Id of host on which the attribute applies to. Pass
	 *                       Null if it applies across hosts.
	 * @param sourceObjId    Object id of the source where the attribute was
	 *                       found.
	 */
	public OsAccountAttribute(Type attributeType, byte[] valueBytes, long osAccountObjId, Long hostId, Long sourceObjId) {
		super(attributeType, valueBytes);

		this.osAccountObjId = osAccountObjId;
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
	 * @param osAccountObjId Obj id of account which the attribute pertains to.
	 * @param sourceObjId    Object id of the source where the attribute was
	 *                       found.
	 * @param hostId         Id of host on which the attribute applies to. Pass
	 *                       Null if it applies across hosts.
	 */
	OsAccountAttribute(BlackboardAttribute.Type attributeType, int valueInt, long valueLong, double valueDouble, String valueString, byte[] valueBytes,
			SleuthkitCase sleuthkitCase, long osAccountObjId, Long hostId, long sourceObjId) {
		
		super( attributeType,
				valueInt, valueLong, valueDouble, valueString, valueBytes,
				sleuthkitCase);
		this.osAccountObjId = osAccountObjId;
		this.hostId = hostId;
		this.sourceObjId = sourceObjId;
	}

	/**
	 * Get the host id for the account attribute.
	 *
	 * @return Optional with Host id.
	 */
	Optional<Long> getHostId() {
		return Optional.ofNullable(hostId);
	}

	/**
	 * Get the object id of account to which this attribute applies.
	 *
	 * @return Account row id.
	 */
	public long getOsAccountObjId() {
		return osAccountObjId;
	}

	/**
	 * Get the object id of the source where the attribute was found.
	 *
	 * @return Object id of source.
	 */
	public Long getSourceObjId() {
		return sourceObjId;
	}

}
