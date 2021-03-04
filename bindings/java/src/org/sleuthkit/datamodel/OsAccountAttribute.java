/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020-2021 Basis Technology Corp.
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
	 * @param attributeType Attribute type.
	 * @param valueInt      Int value.
	 * @param osAccount     Account which the attribute pertains to.
	 * @param host          Host on which the attribute applies to. Pass Null if
	 * @param sourceObj     Source where the attribute was found.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, int valueInt, OsAccount osAccount, Host host, Content sourceObj) {
		super(attributeType, valueInt);

		this.osAccountObjId = osAccount.getId();
		this.hostId = (host != null ? host.getId() : null);
		this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
	}

	/**
	 * Creates an os account attribute with long value.
	 *
	 * @param attributeType Attribute type.
	 * @param valueLong     Long value.
	 * @param osAccount     Account which the attribute pertains to.
	 * @param host          Host on which the attribute applies to. Pass Null if
	 *                      it applies across hosts.
	 * @param sourceObj     Source where the attribute was found.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, long valueLong, OsAccount osAccount, Host host, Content sourceObj) {
		super(attributeType, valueLong);

		this.osAccountObjId = osAccount.getId();
		this.hostId = (host != null ? host.getId() : null);
		this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
	}

	/**
	 * Creates an os account attribute with double value.
	 *
	 * @param attributeType Attribute type.
	 * @param valueDouble   Double value.
	 * @param osAccount     Account which the attribute pertains to.
	 * @param host          Host on which the attribute applies to. Pass Null if
	 *                      it applies across hosts.
	 * @param sourceObj     Source where the attribute was found.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, double valueDouble, OsAccount osAccount, Host host, Content sourceObj) {
		super(attributeType, valueDouble);

		this.osAccountObjId = osAccount.getId();
		this.hostId = (host != null ? host.getId() : null);
		this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
	}

	/**
	 * Creates an os account attribute with string value.
	 *
	 * @param attributeType Attribute type.
	 * @param valueString   String value.
	 * @param osAccount     Account which the attribute pertains to.
	 * @param host          Host on which the attribute applies to. Pass Null if
	 *                      applies across hosts.
	 * @param sourceObj     Source where the attribute was found.
	 */
	public OsAccountAttribute(BlackboardAttribute.Type attributeType, String valueString, OsAccount osAccount, Host host, Content sourceObj) {
		super(attributeType, valueString);

		this.osAccountObjId = osAccount.getId();
		this.hostId = (host != null ? host.getId() : null);
		this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
	}

	/**
	 * Creates an os account attribute with byte-array value.
	 *
	 * @param attributeType Attribute type.
	 * @param valueBytes    Bytes value.
	 * @param osAccount     Account which the attribute pertains to.
	 * @param host          Host on which the attribute applies to. Pass Null if
	 *                      it applies across hosts.
	 * @param sourceObj     Source where the attribute was found.
	 */
	public OsAccountAttribute(Type attributeType, byte[] valueBytes, OsAccount osAccount, Host host, Content sourceObj) {
		super(attributeType, valueBytes);

		this.osAccountObjId = osAccount.getId();
		this.hostId = (host != null ? host.getId() : null);
		this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
	}

	/**
	 * Constructor to be used when creating an attribute after reading the data
	 * from the table.
	 *
	 * @param attributeType Attribute type.
	 * @param valueInt      Int value.
	 * @param valueLong     Long value.
	 * @param valueDouble   Double value.
	 * @param valueString   String value.
	 * @param valueBytes    Bytes value.
	 * @param sleuthkitCase Sleuthkit case.
	 * @param osAccount     Account which the attribute pertains to.
	 * @param host          Host on which the attribute applies to. Pass Null if
	 *                      it applies across hosts.
	 * @param sourceObj     Source where the attribute was found.
	 */
	OsAccountAttribute(BlackboardAttribute.Type attributeType, int valueInt, long valueLong, double valueDouble, String valueString, byte[] valueBytes,
			SleuthkitCase sleuthkitCase, OsAccount osAccount, Host host, Content sourceObj) {

		super(attributeType,
				valueInt, valueLong, valueDouble, valueString, valueBytes,
				sleuthkitCase);
		this.osAccountObjId = osAccount.getId();
		this.hostId = (host != null ? host.getId() : null);
		this.sourceObjId = (sourceObj != null ? sourceObj.getId() : null);
	}

	/**
	 * Get the host id for the account attribute.
	 *
	 * @return Optional with Host id.
	 */
	public Optional<Long> getHostId() {
		return Optional.ofNullable(hostId);
	}

	/**
	 * Get the object id of account to which this attribute applies.
	 *
	 * @return Account row id.
	 */
	public long getOsAccountObjectId() {
		return osAccountObjId;
	}

	/**
	 * Get the object id of the source where the attribute was found.
	 *
	 * @return Object id of source.
	 */
	public Optional<Long> getSourceObjectId() {
		return Optional.ofNullable(sourceObjId);
	}
}
