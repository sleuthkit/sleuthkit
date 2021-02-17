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

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.HostAddress.HostAddressType;

/**
 * Responsible for creating/updating/retrieving host addresses.
 *
 */
public class HostAddressManager {

	private static final Logger LOGGER = Logger.getLogger(HostAddressManager.class.getName());

	private final SleuthkitCase db;

	/**
	 * Construct a HostAddressManager for the given SleuthkitCase.
	 *
	 * @param skCase The SleuthkitCase
	 *
	 */
	HostAddressManager(SleuthkitCase skCase) {
		this.db = skCase;
	}

	/**
	 * Gets an address record with given type and address.
	 *
	 * @param type    Address type.
	 * @param address Address.
	 *
	 * @return Matching address.
	 *
	 * @throws TskCoreException
	 */
	Optional<HostAddress> getHostAddress(HostAddress.HostAddressType type, String address) throws TskCoreException {

		try (CaseDbConnection connection = this.db.getConnection()) {
			return HostAddressManager.this.getHostAddress(type, address, connection);
		}
	}

	/**
	 * Gets an address record with given type and address.
	 *
	 * @param type       Address type.
	 * @param address    Address.
	 * @param connection Connection to use for DB operation.
	 *
	 * @return Matching address.
	 *
	 * @throws TskCoreException
	 */
	private Optional<HostAddress> getHostAddress(HostAddress.HostAddressType type, String address, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT * FROM tsk_host_addresses"
				+ " WHERE LOWER(address) = LOWER('" + address + "')";
		if (type.equals(HostAddress.HostAddressType.DNS_AUTO)) {
			queryString += " AND address_type IN (" + HostAddress.HostAddressType.IPV4.getId() + ", " + HostAddress.HostAddressType.IPV6.getId()
					+ ", " + HostAddress.HostAddressType.HOSTNAME.getId() + ")";
		} else {
			queryString += " AND address_type = " + type.getId();
		}

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				return Optional.of(new HostAddress(db, rs.getLong("id"), HostAddressType.fromID(rs.getInt("address_type")), address));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host address with type = %s and address = %s", type.getName(), address), ex);
		}
	}

	/**
	 * Add a new address with the given type and address. If the address already
	 * exists in the database, the existing entry will be returned.
	 *
	 * @param type    Address type.
	 * @param address Address (case-insensitive).
	 *
	 * @return HostAddress
	 *
	 * @throws TskCoreException
	 */
	HostAddress createHostAddress(HostAddress.HostAddressType type, String address) throws TskCoreException {
		CaseDbConnection connection = this.db.getConnection();
		try {
			return HostAddressManager.this.createHostAddress(type, address, connection);
		} catch (TskCoreException ex) {
			// The insert may have failed because the HostAddress already exists, so
			// try loading it from the database.
			Optional<HostAddress> hostAddress = HostAddressManager.this.getHostAddress(type, address, connection);
			if (hostAddress.isPresent()) {
				return hostAddress.get();
			}
			throw ex;
		} finally {
			connection.close();
		}
	}

	/**
	 * Insert a row in the tsk_host_addresses with the given type and address.
	 *
	 * @param type       Address type.
	 * @param address    Address.
	 * @param connection Database connection to use.
	 *
	 * @return HostAddress.
	 *
	 * @throws TskCoreException
	 */
	private HostAddress createHostAddress(HostAddress.HostAddressType type, String address, CaseDbConnection connection) throws TskCoreException {
		HostAddress.HostAddressType addressType = type;
		if (type.equals(HostAddress.HostAddressType.DNS_AUTO)) {
			addressType = getDNSType(address);
		}

		db.acquireSingleUserCaseWriteLock();
		try {

			// TODO: need to get the correct parent obj id.  
			long parentObjId = 0;
			int objTypeId = TskData.ObjectType.HOST_ADDRESS.getObjectType();

			long objId = db.addObject(parentObjId, objTypeId, connection);

			String hostAddressInsertSQL = "INSERT INTO tsk_host_addresses(id, address_type, address) VALUES (?, ?, ?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(hostAddressInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setLong(1, objId);
			preparedStatement.setInt(2, addressType.getId());
			preparedStatement.setString(3, address.toLowerCase());

			connection.executeUpdate(preparedStatement);
			return new HostAddress(db, objId, addressType, address);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding host address of type = %s, with address = %s", type.getName(), address), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Add a host to address mapping.
	 *
	 * @param host	       Host.
	 * @param hostAddress Address.
	 * @param time        Time at which the mapping was valid.
	 * @param source      Content from where this mapping was derived.
	 *
	 * @throws TskCoreException
	 */
	void mapHostToAddress(Host host, HostAddress hostAddress, Long time, Content source) throws TskCoreException {

		String insertSQL = insertOrIgnore(" INTO tsk_host_address_map(host_id, addr_obj_id, source_obj_id, time) "
				+ " VALUES(?, ?, ?, ?) ");

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection()) {

			PreparedStatement preparedStatement = connection.getPreparedStatement(insertSQL, Statement.NO_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setLong(1, host.getId());
			preparedStatement.setLong(2, hostAddress.getId());
			preparedStatement.setLong(3, source.getId());
			preparedStatement.setLong(4, time);

			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding host address mapping for host name = %s,  with address = %s", host.getName(), hostAddress.getAddress()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get all the addresses that have been mapped to the given host
	 *
	 * @param host Host to get addresses for.
	 *
	 * @return Collection of addresses, may be empty.
	 */
	Set<HostAddress> getHostAddresses(Host host) throws TskCoreException {

		String queryString = "SELECT addr_obj_id FROM tsk_host_address_map "
				+ " WHERE host_id = " + host.getId();

		Set<HostAddress> addresses = new HashSet<>();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				addresses.add(HostAddressManager.this.getHostAddress(rs.getLong("addr_obj_id"), connection));
			}

			return addresses;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses for host " + host.getName()), ex);
		}
	}

	/**
	 * Gets an address for the given object id.
	 *
	 * @param id Object id.
	 *
	 * @return The corresponding HostAddress object.
	 *
	 * @throws TskCoreException
	 */
	HostAddress getHostAddress(long id) throws TskCoreException {
		try (CaseDbConnection connection = this.db.getConnection()) {
			return HostAddressManager.this.getHostAddress(id, connection);
		}
	}

	/**
	 * Gets an address for the given object id.
	 *
	 * @param id Id of the host address.
	 * @param connection Current connection
	 *
	 * @return The corresponding HostAddress.
	 *
	 * @throws TskCoreException
	 */
	private HostAddress getHostAddress(long id, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT * FROM tsk_host_addresses"
				+ " WHERE id = " + id;

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new TskCoreException(String.format("No address found with id = %d", id));
			} else {
				return new HostAddress(db, rs.getLong("id"), HostAddress.HostAddressType.fromID(rs.getInt("address_type")), rs.getString("address"));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host address with id = %d", id), ex);
		}
	}

	/**
	 * Adds a row to the ipAddress table.
	 *
	 * @param dnsNameAddress The DNS name.
	 * @param ipAddress      An IP address associated with the DNS name.
	 * @param time           Timestamp when this relationship was true.
	 * @param source         The source.
	 *
	 * @throws TskCoreException
	 */
	void addHostNameToIpMapping(HostAddress dnsNameAddress, HostAddress ipAddress, Long time, Content source) throws TskCoreException {

		if (dnsNameAddress.getAddressType() != HostAddress.HostAddressType.HOSTNAME) {
			throw new IllegalArgumentException("A host name address is expected.");
		}
		if ((ipAddress.getAddressType() != HostAddress.HostAddressType.IPV4) && (ipAddress.getAddressType() != HostAddress.HostAddressType.IPV6)) {
			throw new IllegalArgumentException("An IPv4/IPv6 address is expected.");
		}

		String insertSQL = insertOrIgnore(" INTO tsk_host_address_dns_ip_map(dns_address_id, ip_address_id, source_obj_id, time) "
				+ " VALUES(?, ?, ?, ?) ");

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection()) {

			PreparedStatement preparedStatement = connection.getPreparedStatement(insertSQL, Statement.NO_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setLong(1, dnsNameAddress.getId());
			preparedStatement.setLong(2, ipAddress.getId());
			preparedStatement.setLong(3, source.getId());
			preparedStatement.setLong(4, time);

			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding host DNS address mapping for DNS name = %s, and IP address = %s", dnsNameAddress.getAddress(), ipAddress.getAddress()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Gets the IP addresses for a given HOSTNAME name.
	 *
	 * @param hostname HOSTNAME name to look for.
	 *
	 * @return Collection of IP Addresses mapped to this dns name. May be empty.
	 *
	 * @throws TskCoreException
	 */
	Set<HostAddress> getIp(String hostname) throws TskCoreException {
		String queryString = "SELECT ip_address_id FROM tsk_host_address_dns_ip_map as map "
				+ " JOIN tsk_host_addresses as addresses "
				+ " ON map.dns_address_id = addresses.id "
				+ " WHERE addresses.address_type = " + HostAddress.HostAddressType.HOSTNAME.getId()
				+ " AND LOWER( addresses.address) = LOWER('" + hostname + "')";

		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {
			Set<HostAddress> IpAddresses = new HashSet<>();
			while (rs.next()) {
				IpAddresses.add(HostAddressManager.this.getHostAddress(rs.getLong("ip_address_id"), connection));
			}
			return IpAddresses;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses for host name: " + hostname), ex);
		}
	}

	/**
	 * Gets the host names for a given IP address.
	 *
	 * @param ipAddress IP address to look for.
	 *
	 * @return All corresponding host names.
	 *
	 * @throws TskCoreException
	 */
	Set<HostAddress> getHostNameByIp(String ipAddress) throws TskCoreException {
		String queryString = "SELECT dns_address_id FROM tsk_host_address_dns_ip_map as map "
				+ " JOIN tsk_host_addresses as addresses "
				+ " ON map.ip_address_id = addresses.id "
				+ " WHERE ( addresses.address_type = " + HostAddress.HostAddressType.IPV4.getId()
				+ " OR  addresses.address_type = " + HostAddress.HostAddressType.IPV6.getId() + ")"
				+ " AND LOWER( addresses.address) = LOWER('" + ipAddress + "')";

		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			Set<HostAddress> dnsNames = new HashSet<>();
			while (rs.next()) {
				dnsNames.add(HostAddressManager.this.getHostAddress(rs.getLong("dns_address_id"), connection));
			}
			return dnsNames;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses for IP address: " + ipAddress), ex);
		}
	}

	/**
	 * Associate the given artifact with a HostAddress.
	 *
	 * @param artifact    The artifact to associate the host address with.
	 * @param hostAddress The host address.
	 */
	void addUsage(BlackboardArtifact artifact, HostAddress hostAddress) throws TskCoreException {
		final String insertSQL = insertOrIgnore(" INTO tsk_host_address_usage(addr_obj_id, artifact_obj_id) "
				+ " VALUES(" + hostAddress.getId() + ", " + artifact.getId() + ") ");

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement()) {
			connection.executeUpdate(s, insertSQL);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error associating host address %s with artifact with id %d", hostAddress.getAddress(), artifact.getId()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Constructs suitable insert or ignore sql query.
	 *
	 * @param sql
	 *
	 * @return SQL string.
	 */
	private String insertOrIgnore(String sql) {
		switch (db.getDatabaseType()) {
			case POSTGRESQL:
				return " INSERT " + sql + " ON CONFLICT DO NOTHING "; //NON-NLS
			case SQLITE:
				return " INSERT OR IGNORE " + sql; //NON-NLS
			default:
				throw new UnsupportedOperationException("Unsupported DB type: " + db.getDatabaseType().name());
		}
	}

	/**
	 * Detects format of address.
	 *
	 * @param address The address.
	 *
	 * @return The detected type.
	 */
	private HostAddress.HostAddressType getDNSType(String address) {
		if (isIPv4(address)) {
			return HostAddress.HostAddressType.IPV4;
		} else if (isIPv6(address)) {
			return HostAddress.HostAddressType.IPV6;
		} else {
			return HostAddress.HostAddressType.HOSTNAME;
		}
	}

	/**
	 * Test if an address is IPv4.
	 *
	 * @param ipAddress The address.
	 *
	 * @return true if it is IPv4 format, false otherwise.
	 */
	private static boolean isIPv4(String ipAddress) {
		boolean isIPv4 = false;

		if (ipAddress != null) {
			try {
				InetAddress inetAddress = InetAddress.getByName(ipAddress);
				isIPv4 = (inetAddress instanceof Inet4Address) && inetAddress.getHostAddress().equals(ipAddress);
			} catch (UnknownHostException ex) {
				return false;
			}
		}

		return isIPv4;
	}

	/**
	 * Test if an address is IPv6.
	 *
	 * @param ipAddress The address.
	 *
	 * @return true if it is IPv4 format, false otherwise.
	 */
	private static boolean isIPv6(String ipAddress) {
		boolean isIPv6 = false;

		if (ipAddress != null) {
			try {
				InetAddress inetAddress = InetAddress.getByName(ipAddress);
				isIPv6 = (inetAddress instanceof Inet6Address);
			} catch (UnknownHostException ex) {
				return false;
			}
		}

		return isIPv6;
	}
}
