/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
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

import java.util.Objects;

/**
 *
 * Abstracts an address associated with a host. A host may have multiple
 * addressed of different types associated with it ant a give time.
 */
public class HostAddress /* RAMAN TBD: implements Content */ {

	private final long id;
	private final HostAddressType addressType;
	private final String address;

	HostAddress(long id, HostAddressType type, String address) {
		this.id = id;
		this.addressType = type;
		this.address = address;
	}

	public long getId() {
		return id;
	}

	public HostAddressType getAddressType() {
		return addressType;
	}

	public String getAddress() {
		return address;
	}

	@Override
	public int hashCode() {
		int hash = 7;
		hash = 53 * hash + (int) (this.id ^ (this.id >>> 32));
		hash = 53 * hash + Objects.hashCode(this.addressType);
		hash = 53 * hash + Objects.hashCode(this.address);
		return hash;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final HostAddress other = (HostAddress) obj;
		if (this.id != other.id) {
			return false;
		}
		
		if (this.addressType != other.addressType) {
			return false;
		}
		
		if ((this.address == null) ? (other.address != null) : !this.address.equals(other.address)) {
			return false;
		}
		
		return true;
	}

	/**
	 * A host may have different types of addresses at a given point in time.
	 */
	public enum HostAddressType {
		DNS(1, "DNS"),
		IPV4(2, "IPv4"),
		IPV6(3, "IPv6"),
		ETHERNETMAC(4, "Ethernet MAC"),
		WIFIMAC(5, "WiFi MAC"),
		BLUETOOTHMAC(6, "BlueTooth MAC");

		private final int id;
		private final String name;

		HostAddressType(int id, String name) {
			this.id = id;
			this.name = name;
		}

		public int getId() {
			return id;
		}

		String getName() {
			return name;
		}

		public static HostAddressType fromID(int typeId) {
			for (HostAddressType type : HostAddressType.values()) {
				if (type.ordinal() == typeId) {
					return type;
				}
			}
			return null;
		}
	}
}
