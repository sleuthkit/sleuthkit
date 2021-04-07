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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
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
	 * An HostAddress Object Id entry is maintained in this cache when a
	 * hostaddress and ip mapping is added. This is here to improve the
	 * performance of {@link #hostNameAndIpMappingExists(long) } check.
	 */
	private final Cache<Long, Byte> recentHostNameAndIpMappingCache = CacheBuilder.newBuilder().maximumSize(200000).build();

	/**
	 * Recently added or accessed Host Address Object Ids are cached. This is
	 * here to improve performance of the
	 * {@link #hostAddressExists(org.sleuthkit.datamodel.HostAddress.HostAddressType, java.lang.String)}
	 * check.
	 */
	private final Cache<String, Long> recentHostAddresstCache = CacheBuilder.newBuilder().maximumSize(200000).build();

	
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
	public Optional<HostAddress> getHostAddress(HostAddress.HostAddressType type, String address) throws TskCoreException {

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
				+ " WHERE LOWER(address) = LOWER(?)";
		if (type.equals(HostAddress.HostAddressType.DNS_AUTO)) {
			queryString += " AND address_type IN (" + HostAddress.HostAddressType.IPV4.getId() + ", " + HostAddress.HostAddressType.IPV6.getId()
					+ ", " + HostAddress.HostAddressType.HOSTNAME.getId() + ")";
		} else {
			queryString += " AND address_type = " + type.getId();
		}

		db.acquireSingleUserCaseReadLock();
		try {
			PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, address);
			try (ResultSet rs = query.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();	// no match found
				} else {
					return Optional.of(new HostAddress(db, rs.getLong("id"), HostAddressType.fromID(rs.getInt("address_type")), address));
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host address with type = %s and address = %s", type.getName(), address), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
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
	public HostAddress newHostAddress(HostAddress.HostAddressType type, String address) throws TskCoreException {
		CaseDbConnection connection = this.db.getConnection();
		try {
			return HostAddressManager.this.newHostAddress(type, address, connection);
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
	private HostAddress newHostAddress(HostAddress.HostAddressType type, String address, CaseDbConnection connection) throws TskCoreException {
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
			recentHostAddresstCache.put(addressType.getId()+"#"+address.toLowerCase(), objId);
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
	public void assignHostToAddress(Host host, HostAddress hostAddress, Long time, Content source) throws TskCoreException {

		String insertSQL = db.getInsertOrIgnoreSQL(" INTO tsk_host_address_map(host_id, addr_obj_id, source_obj_id, time) "
				+ " VALUES(?, ?, ?, ?) ");

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection()) {

			PreparedStatement preparedStatement = connection.getPreparedStatement(insertSQL, Statement.NO_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setLong(1, host.getHostId());
			preparedStatement.setLong(2, hostAddress.getId());
			preparedStatement.setLong(3, source.getId());
			if (time != null) {
				preparedStatement.setLong(4, time);
			} else {
				preparedStatement.setNull(4, java.sql.Types.BIGINT);
			}

			connection.executeUpdate(preparedStatement);
		} catch (SQLException ex) {
			LOGGER.log(Level.SEVERE, null, ex);
			throw new TskCoreException(String.format("Error adding host address mapping for host name = %s,  with address = %s", host.getName(), hostAddress.getAddress()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Get all the addresses that have been assigned to the given host.
	 *
	 * @param host Host to get addresses for.
	 *
	 * @return List of addresses, may be empty.
	 */
	List<HostAddress> getHostAddressesAssignedTo(Host host) throws TskCoreException {

		String queryString = "SELECT addr_obj_id FROM tsk_host_address_map "
				+ " WHERE host_id = " + host.getHostId();

		List<HostAddress> addresses = new ArrayList<>();
		
		db.acquireSingleUserCaseReadLock();
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
		finally {
			db.releaseSingleUserCaseReadLock();
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
	public HostAddress getHostAddress(long id) throws TskCoreException {
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

		db.acquireSingleUserCaseReadLock();
		try (Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, queryString)) {

			if (!rs.next()) {
				throw new TskCoreException(String.format("No address found with id = %d", id));
			} else {
				long objId = rs.getLong("id");
				int type = rs.getInt("address_type");
				String address =  rs.getString("address");
				recentHostAddresstCache.put(type+"#"+address, objId);
				return new HostAddress(db, objId, HostAddress.HostAddressType.fromID(type),address);
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host address with id = %d", id), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
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
	public void addHostNameAndIpMapping(HostAddress dnsNameAddress, HostAddress ipAddress, Long time, Content source) throws TskCoreException {

		try (CaseDbConnection connection = this.db.getConnection()) {
			addHostNameAndIpMapping(dnsNameAddress, ipAddress, time, source, connection);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding host DNS address mapping for DNS name = %s, and IP address = %s", dnsNameAddress.getAddress(), ipAddress.getAddress()), ex);
		} 
	}
	
	/**
	 * Adds a row to the host address dns ip map table.
	 *
	 * @param dnsNameAddress    The DNS name.
	 * @param ipAddress         An IP address associated with the DNS name.
	 * @param time              Timestamp when this relationship was true.
	 * @param source            The source.
	 * @param caseDbTransaction The transaction in the scope of which the
	 *                          operation is to be performed, managed by the
	 *                          caller. Null is not permitted.
	 *
	 * @throws TskCoreException
	 */
	public void addHostNameAndIpMapping(HostAddress dnsNameAddress, HostAddress ipAddress, Long time, Content source, final SleuthkitCase.CaseDbTransaction caseDbTransaction) throws TskCoreException {

		if (Objects.isNull(caseDbTransaction)) {
			throw new TskCoreException(String.format("Error adding host DNS address mapping for DNS name = %s, and IP address = %s, null caseDbTransaction passed to addHostNameAndIpMapping", dnsNameAddress.getAddress(), ipAddress.getAddress()));
		}
		try {
			addHostNameAndIpMapping(dnsNameAddress, ipAddress, time, source, caseDbTransaction.getConnection());
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding host DNS address mapping for DNS name = %s, and IP address = %s", dnsNameAddress.getAddress(), ipAddress.getAddress()), ex);
		} 
	}
	
	/**
	 * Adds a row to the host address dns ip map table.
	 *
	 * @param dnsNameAddress The DNS name.
	 * @param ipAddress      An IP address associated with the DNS name.
	 * @param time           Timestamp when this relationship was true.
	 * @param source         The source.
	 * @param connection     The db connection. Null is not permitted.
	 *
	 * @throws TskCoreException
	 */
	private void addHostNameAndIpMapping(HostAddress dnsNameAddress, HostAddress ipAddress, Long time, Content source, final CaseDbConnection connection) throws  SQLException, TskCoreException {

		if (dnsNameAddress.getAddressType() != HostAddress.HostAddressType.HOSTNAME) {
			throw new TskCoreException("IllegalArguments passed to addHostNameAndIpMapping: A host name address is expected.");
		}
		if ((ipAddress.getAddressType() != HostAddress.HostAddressType.IPV4) && (ipAddress.getAddressType() != HostAddress.HostAddressType.IPV6)) {
			throw new TskCoreException("IllegalArguments passed to addHostNameAndIpMapping:An IPv4/IPv6 address is expected.");
		}
		if (Objects.isNull(connection)) {
			throw new TskCoreException("IllegalArguments passed to addHostNameAndIpMapping: null connection passed to addHostNameAndIpMapping");
		}

		String insertSQL = db.getInsertOrIgnoreSQL(" INTO tsk_host_address_dns_ip_map(dns_address_id, ip_address_id, source_obj_id, time) "
				+ " VALUES(?, ?, ?, ?) ");

		db.acquireSingleUserCaseWriteLock();
		try {
			PreparedStatement preparedStatement = connection.getPreparedStatement(insertSQL, Statement.NO_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setLong(1, dnsNameAddress.getId());
			preparedStatement.setLong(2, ipAddress.getId());
			preparedStatement.setLong(3, source.getId());
			if (time != null) {
				preparedStatement.setLong(4, time);
			} else {
				preparedStatement.setNull(4, java.sql.Types.BIGINT);
			}
			connection.executeUpdate(preparedStatement);
			recentHostNameAndIpMappingCache.put(ipAddress.getId(), new Byte((byte) 1));
			recentHostNameAndIpMappingCache.put(dnsNameAddress.getId(), new Byte((byte) 1));
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	/**
	 * Returns true if addressObjectId is used as either IP or host name
	 * <br>
	 * <b>Note:</b> This api call uses a database connection. Do not invoke within a transaction.
	 * 
	 * @param addressObjectId
	 * @return 
	 * @throws TskCoreException
	 */
	public boolean hostNameAndIpMappingExists(long addressObjectId) throws TskCoreException {

		Byte isPresent = recentHostNameAndIpMappingCache.getIfPresent(addressObjectId);
		
		if(Objects.nonNull(isPresent)){
			return true;
		}
		
		String queryString = "SELECT count(*) as mappingCount FROM tsk_host_address_dns_ip_map WHERE ip_address_id = ? OR dns_address_id = ? ";
		 
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				PreparedStatement ps = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);) {
			ps.clearParameters();
			ps.setLong(1, addressObjectId);
			ps.setLong(2, addressObjectId);
			try (ResultSet rs = ps.executeQuery()) {
				if (!rs.next()) {
					return false;
				} else {
					boolean status = rs.getLong("mappingCount") > 0;
					if(status){
						recentHostNameAndIpMappingCache.put(addressObjectId, new Byte((byte)1));
					}
					return status;
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error looking up host address / Ip mapping for address = " + addressObjectId, ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}
	

	
	/**
	 * Returns ObjectId of HostAddress if it exists.
	 * <br>
	 * <b>Note:</b> This api call uses a database connection. Do not invoke
	 * within a transaction.
	 *
	 * @param type
	 * @param address
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	public Optional<Long> hostAddressExists(HostAddress.HostAddressType type, String address) throws TskCoreException {
		
		Long id = recentHostAddresstCache.getIfPresent(type.getId()+"#"+address.toLowerCase());
		if(Objects.nonNull(id)){
			return Optional.of(id);
		}
		
		String queryString = "SELECT id, address_type FROM tsk_host_addresses"
				+ " WHERE LOWER(address) = LOWER(?)";
		if (type.equals(HostAddress.HostAddressType.DNS_AUTO)) {
			queryString += " AND address_type IN (" + HostAddress.HostAddressType.IPV4.getId() + ", " + HostAddress.HostAddressType.IPV6.getId()
					+ ", " + HostAddress.HostAddressType.HOSTNAME.getId() + ")";
		} else {
			queryString += " AND address_type = " + type.getId();
		}

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);) {
			query.clearParameters();
			query.setString(1, address);
			try (ResultSet rs = query.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();	// no match found
				} else {
					long objId = rs.getLong("id");
					int addrType = rs.getInt("address_type");
					recentHostAddresstCache.put(addrType + "#" + address.toLowerCase(), objId);					
					return Optional.of(objId);
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host address with type = %s and address = %s", type.getName(), address), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets the IP addresses for a given HOSTNAME name.
	 *
	 * @param hostname HOSTNAME name to look for.
	 *
	 * @return List of IP Addresses mapped to this dns name. May be empty.
	 *
	 * @throws TskCoreException
	 */
	public List<HostAddress> getIpAddress(String hostname) throws TskCoreException {
		String queryString = "SELECT ip_address_id FROM tsk_host_address_dns_ip_map as map "
				+ " JOIN tsk_host_addresses as addresses "
				+ " ON map.dns_address_id = addresses.id "
				+ " WHERE addresses.address_type = " + HostAddress.HostAddressType.HOSTNAME.getId()
				+ " AND LOWER( addresses.address) = LOWER(?)";

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()){
			List<HostAddress> IpAddresses = new ArrayList<>();
			PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, hostname);
			try (ResultSet rs = query.executeQuery()) {
				while (rs.next()) {
					long ipAddressObjId = rs.getLong("ip_address_id");
					IpAddresses.add(HostAddressManager.this.getHostAddress(ipAddressObjId, connection));
					recentHostNameAndIpMappingCache.put(ipAddressObjId, new Byte((byte)1)); 
				}
				return IpAddresses;
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses for host name: " + hostname), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
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
	List<HostAddress> getHostNameByIp(String ipAddress) throws TskCoreException {
		String queryString = "SELECT dns_address_id FROM tsk_host_address_dns_ip_map as map "
				+ " JOIN tsk_host_addresses as addresses "
				+ " ON map.ip_address_id = addresses.id "
				+ " WHERE ( addresses.address_type = " + HostAddress.HostAddressType.IPV4.getId()
				+ " OR  addresses.address_type = " + HostAddress.HostAddressType.IPV6.getId() + ")"
				+ " AND LOWER( addresses.address) = LOWER(?)";

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()){
			List<HostAddress> dnsNames = new ArrayList<>();
			PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, ipAddress);
			try (ResultSet rs = query.executeQuery()) {
				while (rs.next()) {
					long dnsAddressId = rs.getLong("dns_address_id");
					dnsNames.add(HostAddressManager.this.getHostAddress(dnsAddressId, connection));
					recentHostNameAndIpMappingCache.put(dnsAddressId, new Byte((byte)1));
				}
				return dnsNames;
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses for IP address: " + ipAddress), ex);
		}
		finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Associate the given artifact with a HostAddress.
	 *
	 * @param content    The content/item using the address.
	 * @param hostAddress The host address.
	 */
	public void addUsage(Content content, HostAddress hostAddress) throws TskCoreException {
		final String insertSQL = db.getInsertOrIgnoreSQL(" INTO tsk_host_address_usage(addr_obj_id, obj_id, data_source_obj_id) "
				+ " VALUES(" + hostAddress.getId() + ", " + content.getId() + ", " + content.getDataSource().getId() + ") ");

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement()) {
			connection.executeUpdate(s, insertSQL);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error associating host address %s with artifact with id %d", hostAddress.getAddress(), content.getId()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
		}
	}

	private final String ADDRESS_USAGE_QUERY = "SELECT addresses.id as id, addresses.address_type as address_type, addresses.address as address "
			+ " FROM tsk_host_address_usage as usage "
			+ " JOIN tsk_host_addresses as addresses "
			+ " ON usage.addr_obj_id = addresses.id ";

	/**
	 * Get all the addresses that have been used by the given content.
	 *
	 * @param content Content to get addresses used for.
	 *
	 * @return List of addresses, may be empty.
	 *
	 * @throws TskCoreException
	 */
	public List<HostAddress> getHostAddressesUsedByContent(Content content) throws TskCoreException {
		String queryString = ADDRESS_USAGE_QUERY
				+ " WHERE usage.obj_id = " + content.getId();

		return getHostAddressesUsed(queryString);
	}

	/**
	 * Get all the addresses that have been used by the given data source.
	 *
	 * @param dataSource Data source to get addresses used for.
	 *
	 * @return List of addresses, may be empty.
	 *
	 * @throws TskCoreException
	 */
	public List<HostAddress> getHostAddressesUsedOnDataSource(Content dataSource) throws TskCoreException {
		String queryString = ADDRESS_USAGE_QUERY
				+ " WHERE usage.data_source_obj_id = " + dataSource.getId();

		return getHostAddressesUsed(queryString);
	}

	/**
	 * Gets the host addresses used by running the given query.
	 *
	 * @param addressesUsedSQL SQL query to run.
	 *
	 * @return List of addresses, may be empty.
	 *
	 * @throws TskCoreException
	 */
	private List<HostAddress> getHostAddressesUsed(String addressesUsedSQL) throws TskCoreException {

		List<HostAddress> addressesUsed = new ArrayList<>();

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement();
				ResultSet rs = connection.executeQuery(s, addressesUsedSQL)) {

			while (rs.next()) {
				addressesUsed.add(new HostAddress(db, rs.getLong("id"), HostAddress.HostAddressType.fromID(rs.getInt("address_type")), rs.getString("address")));
			}
			return addressesUsed;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses used with query string = %s", addressesUsedSQL), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
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
