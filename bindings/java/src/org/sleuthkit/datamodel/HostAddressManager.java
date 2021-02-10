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

import com.google.common.base.Strings;
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
	 * Get the HostAddress with the specified type and address.
	 * Creates on if it does not exist.
	 * 
	 * @param type Address type.
	 * @param address Address
	 * @param transaction Transaction to use.
	 * 
	 * @return HostAddress
	 * @throws TskCoreException 
	 */
	HostAddress getOrCreateAddress(HostAddress.HostAddressType type, String address, SleuthkitCase transaction) throws TskCoreException {
		
		if (Strings.isNullOrEmpty(address) ) {
			throw new IllegalArgumentException("Host address is required.");
		}

		CaseDbConnection connection = transaction.getConnection();

		// First search for host by name
		Optional<HostAddress> hostAddress = getAddress(type, address, connection);
		if (hostAddress.isPresent() ) {
			return hostAddress.get();
		}

		// could'nt find it, create a new host address
		return createHostAddress(type, address, connection);
		
	}
	
	/**
	 * Gets a address record with given type and address.
	 * 
	 * @param type Address type.
	 * @param address Address.
	 * 
	 * @return Matching address.
	 * @throws TskCoreException 
	 */
	Optional<HostAddress> getAddress(HostAddress.HostAddressType type, String address) throws TskCoreException {

		try (CaseDbConnection connection = this.db.getConnection()) {
			return getAddress(type, address, connection);
		}
	}
	
	/**
	 * Gets a address record with given type and address.
	 * 
	 * @param type Address type.
	 * @param address Address.
	 * @param connection Connection to use for DB operation.
	 * 
	 * @return Matching address.
	 * @throws TskCoreException 
	 */
	private Optional<HostAddress> getAddress(HostAddress.HostAddressType type, String address, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT * FROM tsk_host_addresses"
							+ " WHERE LOWER(address) = LOWER('" + address + "')"
							+ " AND address_type = " + type.getId();

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				return Optional.empty();	// no match found
			} else {
				return Optional.of(new HostAddress(rs.getLong("id"), type, address ));
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host address with type = %s and address = %s", type.getName(), address), ex);
		}
	}
	
	/**
	 * Insert  a row in the tsk_host_addresses with the given type and address.
	 * 
	 * @param type Address type.
	 * @param address Address.
	 * @param connection Database connection to use.
	 * 
	 * @return HostAddress.
	 * @throws TskCoreException 
	 */
	private HostAddress createHostAddress(HostAddress.HostAddressType type, String address, CaseDbConnection connection) throws TskCoreException {
		db.acquireSingleUserCaseWriteLock();
		try {
			String hostAddressInsertSQL = "INSERT INTO tsk_host_addresses(address_type, address) VALUES (?, ?)"; // NON-NLS
			PreparedStatement preparedStatement = connection.getPreparedStatement(hostAddressInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setInt(1, type.getId());
			preparedStatement.setString(2, address);

			connection.executeUpdate(preparedStatement);

			// Read back the row id
			try (ResultSet resultSet = preparedStatement.getGeneratedKeys();) {
				if (resultSet.next()) {
					return new HostAddress(resultSet.getLong(1), type, address); //last_insert_rowid()
				} else {
					throw new SQLException("Error executing  " + hostAddressInsertSQL);
				}
			}
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
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
	 * @param transaction Transaction to use.
	 *
	 * @throws TskCoreException
	 */
	void mapHostToAddress(Host host, HostAddress hostAddress, long time, Content source, SleuthkitCase.CaseDbTransaction transaction) throws TskCoreException {

		String insertSQL = insertOrIgnore(" INTO tsk_host_address_map(host_id, address_id, source_obj_id, time) "
											+ " VALUES(?, ?, ?, ?) ");

		CaseDbConnection connection = transaction.getConnection();
		db.acquireSingleUserCaseWriteLock();
		try  {

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
		}
		finally {
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
		
		String queryString = "SELECT address_id FROM tsk_host_address_map " 
							 + " WHERE host_id = " + host.getId();

		Set<HostAddress> addresses = new HashSet<>();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			while (rs.next()) {
				addresses.add(getAddress(rs.getLong("address_id"), connection));
			}

			return addresses;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses"), ex);
		}
		
	} 
	
	/**
	 * Gets an address for the given row id.
	 * 
	 * @param id
	 * @param connection
	 * @return
	 * @throws TskCoreException 
	 */
	private HostAddress getAddress(long id, CaseDbConnection connection) throws TskCoreException {
		String queryString = "SELECT * FROM tsk_host_addresses"
							+ " WHERE id = " + id;

		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new TskCoreException(String.format("No address found with id = %d", id));
			} else {
				return new HostAddress(rs.getLong("id"), HostAddress.HostAddressType.fromID(rs.getInt("address_type")), rs.getString("address") );
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host address with id = %d", id), ex);
		}
	}
	
	/**
	 * Adds a row to the ipAddress table.
	 * 
	 */
	void addHostNameToIpMapping(HostAddress dnsNameAddress, HostAddress ipAddress, long time,  String source, SleuthkitCase.CaseDbTransaction transaction  ) throws TskCoreException {
		
		if (dnsNameAddress.getAddressType() != HostAddress.HostAddressType.DNS) {
			throw new IllegalArgumentException("A DNS Name address is expected.");
		}
		if ((ipAddress.getAddressType() != HostAddress.HostAddressType.IPV4) || (ipAddress.getAddressType() != HostAddress.HostAddressType.IPV6))  {
			throw new IllegalArgumentException("An IPv4/IPv6 address is expected.");
		}
		
		String insertSQL = insertOrIgnore(" INTO tsk_host_address_name_map(dns_address_id, ip_address_id, source, time) "
											+ " VALUES(?, ?, ?, ?) ");

		CaseDbConnection connection = transaction.getConnection();
		db.acquireSingleUserCaseWriteLock();
		try  {

			PreparedStatement preparedStatement = connection.getPreparedStatement(insertSQL, Statement.NO_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setLong(1, dnsNameAddress.getId());
			preparedStatement.setLong(2, ipAddress.getId());
			preparedStatement.setString(3, source);
			preparedStatement.setLong(4, time);

			connection.executeUpdate(preparedStatement);	
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding host DNS address mapping for DNS name = %s, and IP address = %s", dnsNameAddress.getAddress(), ipAddress.getAddress()), ex);
		}
		finally {
			db.releaseSingleUserCaseWriteLock();
		}
		
	}
	
	/**
	 * Gets the IP addresses for a given DNS name.
	 * 
	 * @param dnsName DNS name to look for. 
	 * 
	 * @return Collection of IP Addresses mapped to this dns name. May be empty.
	 * 
	 * @throws TskCoreException 
	 */
	Set<HostAddress> getIp(String dnsName) throws TskCoreException {
		String queryString = "SELECT ip_address_id FROM tsk_host_address_name_map as map "
				+ " JOIN tsk_host_addresses as addresses "
				+ " ON map.dns_address_id = addresses.id "
				+ " WHERE addresses.address_type = " + HostAddress.HostAddressType.DNS
				+ " AND LOWER( addresses.address) = LOWER('" + dnsName + "')";

		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {
			Set<HostAddress> IpAddresses = new HashSet<>();
			while (rs.next()) {
				IpAddresses.add(getAddress(rs.getLong("ip_address_id"), connection));
			} 
			return IpAddresses;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses"), ex);
		}
	}
	
	/**
	 * Gets the host DNS names for a given IP address.
	 *
	 * @param dnsName DNS name to look for.
	 *
	 * @return IP Address, if found.
	 *
	 * @throws TskCoreException
	 */
	Set<HostAddress> getHostNameByIp(String ipAddress) throws TskCoreException {
		String queryString = "SELECT dns_address_id FROM tsk_host_address_name_map as map "
				+ " JOIN tsk_host_addresses as addresses "
				+ " ON map.dns_address_id = addresses.id "
				+ " WHERE ( addresses.address_type = " + HostAddress.HostAddressType.IPV4
				+ " OR  addresses.address_type = " + HostAddress.HostAddressType.IPV6 + ")"
				+ " AND LOWER( addresses.address) = LOWER('" + ipAddress + "')";

		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			Set<HostAddress> dnsNames = new HashSet<>();
			while (rs.next()) {
				dnsNames.add(getAddress(rs.getLong("dns_address_id"), connection));
			} 
			return dnsNames;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses"), ex);
		}
	}
				
	
	/**
	 * Constructs suitable insert or ignore sql query.
	 * 
	 * @param sql 
	 * @return  SQL string. 
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
}
