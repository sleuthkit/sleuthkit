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
public class HostAddress extends AbstractContent {
	
    private final SleuthkitCase sleuthkitCase;
	private final long id;
	private final HostAddressType addressType;
	private final String address;
	

			/**
			 * 	 * @param signature	     A unique signature constructed from realm id and
	 *                       loginName or uniqueId.
			 */
	HostAddress(SleuthkitCase skCase, long id, HostAddressType type, String address) {
		super(skCase, id, address + "(" + type.getName() + ")");
		this.sleuthkitCase = skCase;
		this.id = id;
		this.addressType = type;
		this.address = address;
	}

	@Override
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
	 * Gets the SleuthKit case  database for this
	 * account.
	 *
	 * @return The SleuthKit case object.
	 */
	@Override
	public SleuthkitCase getSleuthkitCase() {
		return sleuthkitCase;
	}
	
	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		// No data to read. 
		return 0;
	}

	@Override
	public void close() {
		// Nothing to close
	}

	@Override
	public long getSize() {
		return 0;
	}
	
	@Override
	public <T> T accept(ContentVisitor<T> v) {
		// TODO		
		throw new UnsupportedOperationException("Not supported yet."); 
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		// TODO
		throw new UnsupportedOperationException("Not supported yet."); 
	}	

	/**
	 * A host may have different types of addresses at a given point in time.
	 */
	public enum HostAddressType {
		DNS_AUTO(0, "DNS Auto Detection"), // Used to auto-select the DNS type from HOSTNAME, IPV4, and IPV6 when creating HostAddresses
		HOSTNAME(1, "Host Name"),
		IPV4(2, "IPv4"),
		IPV6(3, "IPv6"),
		ETHERNET_MAC(4, "Ethernet MAC"),
		WIFI_MAC(5, "WiFi MAC"),
		BLUETOOTH_MAC(6, "BlueTooth MAC");
		
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
