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
import com.google.common.collect.Lists;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;
import org.sleuthkit.datamodel.HostAddress.HostAddressType;
import org.sleuthkit.datamodel.TskData.DbType;

/**
 * Responsible for creating/updating/retrieving host addresses.
 */
public class HostAddressManager {

	private static final Logger LOGGER = Logger.getLogger(HostAddressManager.class.getName());

	private final SleuthkitCase db;
	private final static byte DEFAULT_MAPPING_CACHE_VALUE = 1;

	/**
	 * Chunk size for the bulk read methods on SQLite, which has no array
	 * parameter type and so has to fall back to an IN list. Sized under the
	 * historical SQLITE_MAX_VARIABLE_NUMBER default of 999. PostgreSQL passes
	 * the whole set as a single array parameter and is never chunked.
	 */
	private final static int SQLITE_CHUNK_SIZE = 900;

	/**
	 * An HostAddress Object Id entry is maintained in this cache when a
	 * hostaddress and ip mapping is added. This is here to improve the
	 * performance of {@link #hostNameAndIpMappingExists(long) } check.
	 */
	private final Cache<Long, Byte> recentHostNameAndIpMappingCache = CacheBuilder.newBuilder().maximumSize(200000).build();

	/**
	 * Recently added or accessed Host Address Objects are cached. This is
	 * here to improve performance of the
	 * {@link #hostAddressExists(org.sleuthkit.datamodel.HostAddress.HostAddressType, java.lang.String)}
	 * check as well as the {@link #getHostAddress(org.sleuthkit.datamodel.HostAddress.HostAddressType, java.lang.String) }
	 */
	private final Cache<String, HostAddress> recentHostAddressCache = CacheBuilder.newBuilder().maximumSize(200000).build();

	/**
	 * Recently added host address usage is cached. This is intended to improve 
	 * the performance of {@link #addUsage(org.sleuthkit.datamodel.Content, org.sleuthkit.datamodel.HostAddress) }
	 * Key: DatasourceId # Host Id # Content Id. Value has no significance. it will be set to true if there is 
	 * a value in cache for the key.
	 */
	private final Cache<String, Boolean> hostAddressUsageCache = CacheBuilder.newBuilder().maximumSize(200000).build();

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

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			return HostAddressManager.this.getHostAddress(type, address, connection);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Bulk form of {@link #getHostAddress(HostAddress.HostAddressType, java.lang.String)}.
	 * Reads every supplied address under a single case read lock instead of one
	 * lock acquisition per address.
	 * <br>
	 * <b>Note:</b> This api call uses a database connection. Do not invoke
	 * within a transaction.
	 *
	 * @param type      Address type. DNS_AUTO is resolved per address, so one
	 *                  batch may span IPV4 and IPV6.
	 * @param addresses Addresses to look up. Duplicates are collapsed. Empty
	 *                  returns an empty map without issuing SQL.
	 *
	 * @return The addresses that were found, keyed by the caller's supplied
	 *         string rather than the normalized form, so callers do not have to
	 *         replicate normalization. Addresses with no row are absent.
	 *
	 * @throws TskCoreException
	 */
	public Map<String, HostAddress> getHostAddresses(HostAddress.HostAddressType type, Collection<String> addresses) throws TskCoreException {

		if (type == null) {
			throw new TskCoreException("type is required");
		}
		if (addresses == null) {
			throw new TskCoreException("addresses is required");
		}

		/*
		 * Normalize once. The query matches on the stored form (normalized and
		 * lower cased), but the returned map is keyed by what the caller passed
		 * in, so lookupKeysByStored carries us back.
		 */
		Map<String, HostAddress> results = new HashMap<>();
		Map<String, List<String>> lookupKeysByStored = new LinkedHashMap<>();
		Map<String, HostAddressType> typesByStored = new HashMap<>();
		for (String address : addresses) {
			if (address == null) {
				continue;
			}
			HostAddressType addressType = type.equals(HostAddress.HostAddressType.DNS_AUTO) ? getDNSType(address) : type;
			String stored = getNormalizedAddress(address).toLowerCase();

			/*
			 * Keyed on the resolved type and the stored form, which is what
			 * every write to this cache uses. The single-row path probes with
			 * the caller's type instead, so a DNS_AUTO lookup there can never
			 * hit an entry it just wrote; probing the written key only means
			 * more hits for the same address, never a different one.
			 */
			HostAddress cached = recentHostAddressCache.getIfPresent(createRecentHostAddressKey(addressType, stored));
			if (Objects.nonNull(cached)) {
				results.put(address, cached);
				continue;
			}
			lookupKeysByStored.computeIfAbsent(stored, k -> new ArrayList<>()).add(address);
			typesByStored.put(stored, addressType);
		}

		if (lookupKeysByStored.isEmpty()) {
			return results;
		}

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			/*
			 * Matched on address alone and filtered by type in memory. A batch
			 * built from DNS_AUTO can carry more than one concrete type, and
			 * (address_type, address) is effectively unique, so this stays a
			 * single statement instead of one per type.
			 */
			for (List<String> chunk : chunkedStrings(new ArrayList<>(lookupKeysByStored.keySet()))) {
				readHostAddressesByAddress(connection, chunk, typesByStored, lookupKeysByStored, results);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error bulk reading host addresses of type " + type.getName(), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
		return results;
	}

	/**
	 * Reads one chunk of addresses and folds the rows into the result map.
	 *
	 * @param connection         Connection to use.
	 * @param chunk              Stored (normalized, lower cased) addresses.
	 * @param typesByStored      Expected concrete type per stored address.
	 * @param lookupKeysByStored The caller's original strings per stored address.
	 * @param results            Accumulator, keyed by the caller's strings.
	 */
	private void readHostAddressesByAddress(CaseDbConnection connection, List<String> chunk,
			Map<String, HostAddressType> typesByStored, Map<String, List<String>> lookupKeysByStored,
			Map<String, HostAddress> results) throws SQLException, TskCoreException {

		boolean isPostgres = db.getDatabaseType().equals(DbType.POSTGRESQL);
		String queryString = "SELECT id, address_type, address FROM tsk_host_addresses WHERE address "
				+ (isPostgres ? "= ANY(?::text[])" : "IN (" + questionMarks(chunk.size()) + ")");

		PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
		query.clearParameters();
		if (isPostgres) {
			query.setArray(1, connection.getConnection().createArrayOf("text", chunk.toArray(new String[0])));
		} else {
			for (int i = 0; i < chunk.size(); i++) {
				query.setString(i + 1, chunk.get(i));
			}
		}

		try (ResultSet rs = query.executeQuery()) {
			while (rs.next()) {
				String stored = rs.getString("address");
				HostAddressType rowType = HostAddressType.fromID(rs.getInt("address_type"));
				if (!rowType.equals(typesByStored.get(stored))) {
					continue;
				}
				HostAddress hostAddress = new HostAddress(db, rs.getLong("id"), rowType, stored);
				recentHostAddressCache.put(createRecentHostAddressKey(rowType, stored), hostAddress);
				for (String callerKey : lookupKeysByStored.getOrDefault(stored, Collections.emptyList())) {
					results.put(callerKey, hostAddress);
				}
			}
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
		
		HostAddress hostAddress = recentHostAddressCache.getIfPresent(createRecentHostAddressKey(type, address));
		if (Objects.nonNull(hostAddress)) {
			return Optional.of(hostAddress);
		}
		HostAddress.HostAddressType addressType = type;
		if (type.equals(HostAddress.HostAddressType.DNS_AUTO)) {
			addressType = getDNSType(address);
		}
		String normalizedAddress = getNormalizedAddress(address);
		String queryString = "SELECT * FROM tsk_host_addresses"
				+ " WHERE address = ?  AND address_type = ?";			
		try {
			PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, normalizedAddress.toLowerCase());
			query.setInt(2, addressType.getId());
			try (ResultSet rs = query.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();	// no match found
				} else {
					HostAddress newHostAddress = new HostAddress(db, rs.getLong("id"), HostAddressType.fromID(rs.getInt("address_type")), rs.getString("address"));
					recentHostAddressCache.put(createRecentHostAddressKey(newHostAddress.getAddressType(), normalizedAddress), newHostAddress);
					return Optional.of(newHostAddress);					
				}
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host address with type = %s and address = %s", type.getName(), address), ex);
		} 
	}

	/**
	 * Create a key string for use as a cache key.
	 *
	 * @param type    Address type.
	 * @param address Address.
	 *
	 * @return Cache key defined as typeId + # + address lowercased.
	 */
	private String createRecentHostAddressKey(HostAddressType type, String address) {
		return createRecentHostAddressKey(type.getId(), address);
	}

	/**
	 * Create a key string for use as a cache key.
	 *
	 * @param typeId  Address type Id.
	 * @param address Address.
	 *
	 * @return Cache key defined as typeId + # + address lowercased.
	 */
	private String createRecentHostAddressKey(int typeId, String address) {
		return typeId + "#" + address.toLowerCase();
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
		db.acquireSingleUserCaseWriteLock();
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
			db.releaseSingleUserCaseWriteLock();
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
		
		String normalizedAddress = getNormalizedAddress(address);
		// This prevents orphaned objects and ensures we return the existing valid object.
		Optional<HostAddress> existingAddr = getHostAddress(addressType, normalizedAddress, connection);
		if (existingAddr.isPresent()) {
			return existingAddr.get();
		}
		try {

			// TODO: need to get the correct parent obj id.  
			long parentObjId = 0;
			int objTypeId = TskData.ObjectType.HOST_ADDRESS.getObjectType();

			long objId = db.addObject(parentObjId, objTypeId, connection);

			String hostAddressInsertSQL = "INSERT INTO tsk_host_addresses(id, address_type, address) VALUES (?, ?, ?) "; //NON-NLS
				
			PreparedStatement preparedStatement = connection.getPreparedStatement(hostAddressInsertSQL, Statement.RETURN_GENERATED_KEYS);

			preparedStatement.clearParameters();
			preparedStatement.setLong(1, objId);
			preparedStatement.setInt(2, addressType.getId());
			preparedStatement.setString(3, normalizedAddress.toLowerCase());

			connection.executeUpdate(preparedStatement);
			HostAddress hostAddress =  new HostAddress(db, objId, addressType, normalizedAddress);
			recentHostAddressCache.put(createRecentHostAddressKey(addressType, normalizedAddress), hostAddress);
			return hostAddress;
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding host address of type = %s, with address = %s", type.getName(), address), ex);
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
	public List<HostAddress> getHostAddressesAssignedTo(Host host) throws TskCoreException {

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
		} finally {
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
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			return HostAddressManager.this.getHostAddress(id, connection);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets an address for the given object id.
	 *
	 * @param id         Id of the host address.
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
				long objId = rs.getLong("id");
				int type = rs.getInt("address_type");
				String address = rs.getString("address");
				HostAddress hostAddress = new HostAddress(db, objId, HostAddress.HostAddressType.fromID(type), address);
				recentHostAddressCache.put(createRecentHostAddressKey(type, address), hostAddress);
				return hostAddress;
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
	public void addHostNameAndIpMapping(HostAddress dnsNameAddress, HostAddress ipAddress, Long time, Content source) throws TskCoreException {

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			addHostNameAndIpMapping(dnsNameAddress, ipAddress, time, source, connection);
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error adding host DNS address mapping for DNS name = %s, and IP address = %s", dnsNameAddress.getAddress(), ipAddress.getAddress()), ex);
		} finally {
			db.releaseSingleUserCaseWriteLock();
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
	private void addHostNameAndIpMapping(HostAddress dnsNameAddress, HostAddress ipAddress, Long time, Content source, final CaseDbConnection connection) throws SQLException, TskCoreException {

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
		recentHostNameAndIpMappingCache.put(ipAddress.getId(), DEFAULT_MAPPING_CACHE_VALUE);
		recentHostNameAndIpMappingCache.put(dnsNameAddress.getId(), DEFAULT_MAPPING_CACHE_VALUE);
	}

	/**
	 * Returns true if addressObjectId is used as either IP or host name
	 * <br>
	 * <b>Note:</b> This api call uses a database connection. Do not invoke
	 * within a transaction.
	 *
	 * @param addressObjectId
	 *
	 * @return
	 *
	 * @throws TskCoreException
	 */
	public boolean hostNameAndIpMappingExists(long addressObjectId) throws TskCoreException {

		Byte isPresent = recentHostNameAndIpMappingCache.getIfPresent(addressObjectId);

		if (Objects.nonNull(isPresent)) {
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
					if (status) {
						recentHostNameAndIpMappingCache.put(addressObjectId, DEFAULT_MAPPING_CACHE_VALUE);
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

		HostAddress hostAddress = recentHostAddressCache.getIfPresent(createRecentHostAddressKey(type, address));
		if (Objects.nonNull(hostAddress)) {
			return Optional.of(hostAddress.getId());
		}

		HostAddress.HostAddressType addressType = type;
		if (type.equals(HostAddress.HostAddressType.DNS_AUTO)) {
			addressType = getDNSType(address);
		} 
		String normalizedAddress = getNormalizedAddress(address);
		
		String queryString = "SELECT id, address_type, address FROM tsk_host_addresses"
				+ " WHERE address = ?  AND address_type = ?"; 

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection();
				PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);) {
			query.clearParameters();
			query.setString(1, normalizedAddress.toLowerCase());
			query.setInt(2, addressType.getId());
			try (ResultSet rs = query.executeQuery()) {
				if (!rs.next()) {
					return Optional.empty();	// no match found
				} else {
					long objId = rs.getLong("id");
					int addrType = rs.getInt("address_type");
					String addr = rs.getString("address");
					HostAddress hostAddr = new HostAddress(db, objId, HostAddress.HostAddressType.fromID(addrType), addr);
					recentHostAddressCache.put(createRecentHostAddressKey(addrType, normalizedAddress), hostAddr);					
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
				+ " AND addresses.address = ?";

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			List<HostAddress> IpAddresses = new ArrayList<>();
			PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, hostname.toLowerCase());
			try (ResultSet rs = query.executeQuery()) {
				while (rs.next()) {
					long ipAddressObjId = rs.getLong("ip_address_id");
					IpAddresses.add(HostAddressManager.this.getHostAddress(ipAddressObjId, connection));
					recentHostNameAndIpMappingCache.put(ipAddressObjId, DEFAULT_MAPPING_CACHE_VALUE);
				}
				return IpAddresses;
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses for host name: " + hostname), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Gets the IP addresses mapped to each of the given DNS name addresses,
	 * keyed by the name address itself.
	 *
	 * <p>
	 * Bulk replacement for the per-address sequence of
	 * {@link #getHostAddress(long)}, {@link #hostNameAndIpMappingExists(long)}
	 * and {@link #getIpAddress(java.lang.String)}: the key supplies the name
	 * address, an empty value stands in for the "no mapping" answer, and a
	 * non-empty value is the mapped IP list. Everything is read under a single
	 * case read lock, and the IP rows are joined rather than fetched one query
	 * per row.</p>
	 *
	 * <p>
	 * Follows the {@code dns_address_id -> ip_address_id} direction only, which
	 * is the whole story for a HOSTNAME address:
	 * {@link #addHostNameAndIpMapping(HostAddress, HostAddress, java.lang.Long, Content)}
	 * rejects anything else on the name side. Passing an IP address id yields an
	 * empty list even when it is mapped; a bulk form of the reverse lookup would
	 * be a separate addition.</p>
	 * <br>
	 * <b>Note:</b> This api call uses a database connection. Do not invoke
	 * within a transaction.
	 *
	 * @param dnsAddressObjectIds Address object ids to look up. Duplicates are
	 *                            collapsed. Empty returns an empty map without
	 *                            issuing SQL.
	 *
	 * @return The addresses that were found, each mapped to its IP addresses.
	 *         An address that exists but has no mapping is present with an empty
	 *         list. An id with no row in tsk_host_addresses is absent entirely -
	 *         note that {@link #getHostAddress(long)} throws in that case.
	 *
	 * @throws TskCoreException
	 */
	public Map<HostAddress, List<HostAddress>> getHostAddressMappings(Collection<Long> dnsAddressObjectIds) throws TskCoreException {

		if (dnsAddressObjectIds == null) {
			throw new TskCoreException("dnsAddressObjectIds is required");
		}

		Set<Long> ids = new LinkedHashSet<>(dnsAddressObjectIds);
		ids.remove(null);
		if (ids.isEmpty()) {
			return Collections.emptyMap();
		}

		Map<HostAddress, List<HostAddress>> results = new LinkedHashMap<>();
		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			for (List<Long> chunk : chunkedLongs(new ArrayList<>(ids))) {
				readHostAddressMappings(connection, chunk, results);
			}
		} catch (SQLException ex) {
			throw new TskCoreException("Error bulk reading host address mappings", ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
		return results;
	}

	/**
	 * Reads one chunk of name addresses plus their mapped IPs and folds the rows
	 * into the result map.
	 *
	 * @param connection Connection to use.
	 * @param chunk      Address object ids.
	 * @param results    Accumulator.
	 */
	private void readHostAddressMappings(CaseDbConnection connection, List<Long> chunk,
			Map<HostAddress, List<HostAddress>> results) throws SQLException, TskCoreException {

		boolean isPostgres = db.getDatabaseType().equals(DbType.POSTGRESQL);
		/*
		 * Left joined so that a name address with no mapping still comes back -
		 * that absence is the signal the caller branches on, and losing it would
		 * silently turn "not mapped yet" into "no such address".
		 */
		String queryString = "SELECT a.id, a.address_type, a.address,"
				+ " ip.id AS ip_id, ip.address_type AS ip_address_type, ip.address AS ip_address"
				+ " FROM tsk_host_addresses a"
				+ " LEFT JOIN tsk_host_address_dns_ip_map m ON m.dns_address_id = a.id"
				+ " LEFT JOIN tsk_host_addresses ip ON ip.id = m.ip_address_id"
				+ " WHERE a.id "
				+ (isPostgres ? "= ANY(?::bigint[])" : "IN (" + questionMarks(chunk.size()) + ")");

		PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
		query.clearParameters();
		if (isPostgres) {
			query.setArray(1, connection.getConnection().createArrayOf("bigint", chunk.toArray(new Long[0])));
		} else {
			for (int i = 0; i < chunk.size(); i++) {
				query.setLong(i + 1, chunk.get(i));
			}
		}

		// One row per mapping, so a name with several IPs arrives as several rows.
		Map<Long, HostAddress> nameAddressesById = new HashMap<>();
		try (ResultSet rs = query.executeQuery()) {
			while (rs.next()) {
				long nameId = rs.getLong("id");
				HostAddress nameAddress = nameAddressesById.get(nameId);
				if (Objects.isNull(nameAddress)) {
					HostAddressType nameType = HostAddressType.fromID(rs.getInt("address_type"));
					String nameValue = rs.getString("address");
					nameAddress = new HostAddress(db, nameId, nameType, nameValue);
					nameAddressesById.put(nameId, nameAddress);
					recentHostAddressCache.put(createRecentHostAddressKey(nameType, nameValue), nameAddress);
					results.put(nameAddress, new ArrayList<>());
				}

				rs.getLong("ip_id");
				if (rs.wasNull()) {
					continue;	// left join miss: exists, but not mapped
				}

				HostAddressType ipType = HostAddressType.fromID(rs.getInt("ip_address_type"));
				String ipValue = rs.getString("ip_address");
				HostAddress ipAddress = new HostAddress(db, rs.getLong("ip_id"), ipType, ipValue);
				recentHostAddressCache.put(createRecentHostAddressKey(ipType, ipValue), ipAddress);

				// Same bookkeeping the single-row mapping paths do.
				recentHostNameAndIpMappingCache.put(nameId, DEFAULT_MAPPING_CACHE_VALUE);
				recentHostNameAndIpMappingCache.put(ipAddress.getId(), DEFAULT_MAPPING_CACHE_VALUE);

				results.get(nameAddress).add(ipAddress);
			}
		}
	}

	/**
	 * Splits ids into chunks the database can take in one statement. PostgreSQL
	 * passes the whole set as a single array parameter, so it is never chunked.
	 *
	 * @param ids The ids.
	 *
	 * @return The chunks.
	 */
	private List<List<Long>> chunkedLongs(List<Long> ids) {
		return db.getDatabaseType().equals(DbType.POSTGRESQL)
				? Collections.singletonList(ids)
				: Lists.partition(ids, SQLITE_CHUNK_SIZE);
	}

	/**
	 * Splits addresses into chunks the database can take in one statement.
	 *
	 * @param addresses The addresses.
	 *
	 * @return The chunks.
	 */
	private List<List<String>> chunkedStrings(List<String> addresses) {
		return db.getDatabaseType().equals(DbType.POSTGRESQL)
				? Collections.singletonList(addresses)
				: Lists.partition(addresses, SQLITE_CHUNK_SIZE);
	}

	/**
	 * Builds a comma separated run of bind placeholders for an IN list.
	 *
	 * @param count How many.
	 *
	 * @return "?, ?, ?" and so on.
	 */
	private static String questionMarks(int count) {
		return Collections.nCopies(count, "?").stream().collect(Collectors.joining(", "));
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
				+ " AND addresses.address = ?";

		db.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = this.db.getConnection()) {
			List<HostAddress> dnsNames = new ArrayList<>();
			PreparedStatement query = connection.getPreparedStatement(queryString, Statement.NO_GENERATED_KEYS);
			query.clearParameters();
			query.setString(1, ipAddress.toLowerCase());
			try (ResultSet rs = query.executeQuery()) {
				while (rs.next()) {
					long dnsAddressId = rs.getLong("dns_address_id");
					dnsNames.add(HostAddressManager.this.getHostAddress(dnsAddressId, connection));
					recentHostNameAndIpMappingCache.put(dnsAddressId, DEFAULT_MAPPING_CACHE_VALUE);
				}
				return dnsNames;
			}
		} catch (SQLException ex) {
			throw new TskCoreException(String.format("Error getting host addresses for IP address: " + ipAddress), ex);
		} finally {
			db.releaseSingleUserCaseReadLock();
		}
	}

	/**
	 * Associate the given artifact with a HostAddress.
	 *
	 * @param content     The content/item using the address.
	 * @param hostAddress The host address.
	 */
	public void addUsage(Content content, HostAddress hostAddress) throws TskCoreException {
		
		String key = content.getDataSource().getId() + "#" + hostAddress.getId() + "#" + content.getId();
		Boolean cachedValue = hostAddressUsageCache.getIfPresent(key);
		if (null != cachedValue) {
			return;
		}
		
		final String insertSQL = db.getInsertOrIgnoreSQL(" INTO tsk_host_address_usage(addr_obj_id, obj_id, data_source_obj_id) "
				+ " VALUES(" + hostAddress.getId() + ", " + content.getId() + ", " + content.getDataSource().getId() + ") ");

		db.acquireSingleUserCaseWriteLock();
		try (CaseDbConnection connection = this.db.getConnection();
				Statement s = connection.createStatement()) {
			connection.executeUpdate(s, insertSQL);
			hostAddressUsageCache.put(key, true);
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

	private static final Pattern IPV4_PATTERN =
            Pattern.compile("^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\\.(?!$)|$)){4}$");
	/**
	 * Test if an address is IPv4.
	 *
	 * @param ipAddress The address.
	 *
	 * @return true if it is IPv4 format, false otherwise.
	 */
	private static boolean isIPv4(String ipAddress) {
		if (ipAddress != null) {
			return IPV4_PATTERN.matcher(ipAddress).matches();
		}
		return false;
	}

	
	// IPV6 address examples:
	//		Standard: 684D:1111:222:3333:4444:5555:6:77
	//		Compressed: 1234:fd2:5621:1:89::4500
	//		With zone/interface specifier: fe80::1ff:fe23:4567:890a%eth2 
	//									   fe80::1ff:fe23:4567:890a%3
	private static final Pattern IPV6_STD_PATTERN = 
            Pattern.compile("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(%.+)?$");
    private static final Pattern IPV6_HEX_COMPRESSED_PATTERN = 
            Pattern.compile("^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)(%.+)?$");

	
    private static boolean isIPv6StdAddress(final String input) {
        return IPV6_STD_PATTERN.matcher(input).matches();
    }
    private static boolean isIPv6HexCompressedAddress(final String input) {
        return IPV6_HEX_COMPRESSED_PATTERN.matcher(input).matches();
    }
	
	/**
	 * Test if an address is IPv6.
	 *
	 * @param ipAddress The address.
	 *
	 * @return true if it is IPv6 format, false otherwise.
	 */
	private static boolean isIPv6(String ipAddress) {
	
		if (ipAddress != null) {
			 return isIPv6StdAddress(ipAddress) || isIPv6HexCompressedAddress(ipAddress);
		}

		return false;
	}
	
	/**
	 * Normalizes an address.
	 * 
	 * It intentionally does NOT convert to lowercase so that the case may be
	 * preserved, and only converted where needed.
	 *
	 * @param address
	 *
	 * @return Normalized address.
	 */
	private static String getNormalizedAddress(String address) {
		
		String normalizedAddress = address;
		
		if (isIPv6(address)) {
			normalizedAddress = getNormalizedIPV6Address(address);
		}
		
		return normalizedAddress;
	}
	
	/**
	 * Normalize an IPv6 address:
	 *  - removing the zone/interface specifier if one exists.
	 *
	 * It intentionally does NOT convert to lowercase so that the case may be
	 * preserved, and only converted where needed.
	 *
	 * @param address Address to normalize. 
	 *
	 * @return Normalized IPv6 address.
	 */
	private static String getNormalizedIPV6Address(String address) {
		
		String normalizedAddress = address;
		if ( normalizedAddress.contains("%") ) {
			normalizedAddress = normalizedAddress.substring(0, normalizedAddress.indexOf("%"));
		}
		
		return normalizedAddress;
	}
}

