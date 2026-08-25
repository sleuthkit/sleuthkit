/*
 * Sleuth Kit Data Model
 *
 * Copyright 2026 Basis Technology Corp.
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

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import org.junit.BeforeClass;
import org.junit.Test;
import org.sleuthkit.datamodel.HostAddress.HostAddressType;

/**
 * Functional tests for the bulk host address APIs:
 * {@link HostAddressManager#getHostAddressMappings(java.util.Collection)} and
 * {@link HostAddressManager#getHostAddresses(HostAddress.HostAddressType, java.util.Collection)}.
 *
 * <p>
 * The load bearing assertion throughout is <b>equivalence with the single row
 * methods</b>: the bulk form has to return exactly what looping
 * {@link HostAddressManager#getHostAddress(long)},
 * {@link HostAddressManager#hostNameAndIpMappingExists(long)} and
 * {@link HostAddressManager#getIpAddress(java.lang.String)} would have
 * returned, because callers are being migrated off those one at a time.</p>
 *
 * <p>
 * Runs against SQLite (suite convention), which exercises the chunked IN list
 * path. To exercise the PostgreSQL array parameter path, uncomment the
 * connection block in {@link #setUpClass} and point it at a test instance.</p>
 */
public class BatchedHostAddressTest {

	private static final Logger LOGGER = Logger.getLogger(BatchedHostAddressTest.class.getName());

	private static final String TEST_DB = "BatchedHostAddressTest.db";

	/**
	 * Enough addresses to cross the SQLite chunk boundary of 900 and prove the
	 * chunks are merged rather than the last one winning.
	 */
	private static final int CHUNK_CROSSING_COUNT = 905;

	private static SleuthkitCase caseDB;
	private static String dbPath = null;
	private static Image image = null;
	private static long dataSourceId = 0;

	public BatchedHostAddressTest() {
	}

	@BeforeClass
	public static void setUpClass() {
		String tempDirPath = System.getProperty("java.io.tmpdir");
		try {
			dbPath = Paths.get(tempDirPath, TEST_DB).toString();
			java.io.File dbFile = new java.io.File(dbPath);
			dbFile.delete();
			if (dbFile.getParentFile() != null) {
				dbFile.getParentFile().mkdirs();
			}

			caseDB = SleuthkitCase.newCase(dbPath);

			// Uncomment to manually exercise the PostgreSQL array parameter path.
			// CaseDbConnectionInfo connectionInfo = new CaseDbConnectionInfo("localhost", "5432", "ct_user", "ct_user_abc", TskData.DbType.POSTGRESQL);
			// caseDB = SleuthkitCase.newCase("TskBatchedHostAddressTest", connectionInfo, tempDirPath);

			SleuthkitCase.CaseDbTransaction trans = caseDB.beginTransaction();
			image = caseDB.addImage(TskData.TSK_IMG_TYPE_ENUM.TSK_IMG_TYPE_DETECT, 512, 1024, "",
					Collections.emptyList(), "America/NewYork", null, null, null,
					"BatchedHostAddressTestImage", trans);
			trans.commit();

			dataSourceId = image.getId();

			System.out.println("BatchedHostAddressTest DB created at: " + dbPath);
		} catch (TskCoreException ex) {
			LOGGER.log(Level.SEVERE, "Failed to set up BatchedHostAddressTest", ex);
			fail("Set-up failed: " + ex.getMessage());
		}
	}

	@AfterClass
	public static void tearDownClass() {
	}

	// ---------- helpers ----------

	private static HostAddressManager mgr() {
		return caseDB.getHostAddressManager();
	}

	private static HostAddress name(String hostName) throws TskCoreException {
		return mgr().newHostAddress(HostAddressType.HOSTNAME, hostName);
	}

	private static HostAddress ip(String address) throws TskCoreException {
		return mgr().newHostAddress(HostAddressType.DNS_AUTO, address);
	}

	private static void mapNameToIp(HostAddress hostName, HostAddress ipAddress) throws TskCoreException {
		mgr().addHostNameAndIpMapping(hostName, ipAddress, 1L, image);
	}

	/**
	 * What the bulk call returns, re-keyed by address id so it can be compared
	 * against the single row methods.
	 */
	private static Map<Long, HostAddress> addressesById(List<Long> ids) throws TskCoreException {
		Map<Long, HostAddress> byId = new HashMap<>();
		mgr().getHostAddressMappings(ids).keySet().forEach(address -> byId.put(address.getId(), address));
		return byId;
	}

	// ---------- tests ----------

	/**
	 * A mapped name must come back with exactly the IPs the single row lookups
	 * report, and its address must be the key.
	 */
	@Test
	public void testMappedNameMatchesSingularLookups() throws TskCoreException {
		HostAddress host = name("mapped.example.com");
		HostAddress ipv4 = ip("93.184.216.34");
		HostAddress ipv6 = ip("2606:2800:220:1:248:1893:25c8:1946");
		mapNameToIp(host, ipv4);
		mapNameToIp(host, ipv6);

		Map<HostAddress, List<HostAddress>> bulk = mgr().getHostAddressMappings(Arrays.asList(host.getId()));

		assertEquals("one name in, one name out", 1, bulk.size());
		HostAddress key = bulk.keySet().iterator().next();
		assertEquals("the key is the name address the singular getHostAddress returns",
				mgr().getHostAddress(host.getId()), key);

		Set<Long> bulkIpIds = bulk.get(key).stream().map(HostAddress::getId).collect(Collectors.toSet());
		Set<Long> singularIpIds = mgr().getIpAddress("mapped.example.com").stream()
				.map(HostAddress::getId).collect(Collectors.toSet());

		assertEquals("bulk must return what getIpAddress returns", singularIpIds, bulkIpIds);
		assertEquals(2, bulkIpIds.size());
		assertTrue(bulkIpIds.contains(ipv4.getId()));
		assertTrue(bulkIpIds.contains(ipv6.getId()));
		assertTrue("the singular existence probe agrees", mgr().hostNameAndIpMappingExists(host.getId()));
	}

	/**
	 * The distinction the callers branch on: an address that exists but has no
	 * mapping is <b>present with an empty list</b>, not missing. Losing this
	 * would silently turn "not mapped yet" into "no such address".
	 */
	@Test
	public void testUnmappedNameIsPresentWithEmptyList() throws TskCoreException {
		HostAddress host = name("unmapped.example.com");

		Map<HostAddress, List<HostAddress>> bulk = mgr().getHostAddressMappings(Arrays.asList(host.getId()));

		assertEquals(1, bulk.size());
		HostAddress key = bulk.keySet().iterator().next();
		assertEquals(host.getId(), key.getId());
		assertNotNull("present, not absent", bulk.get(key));
		assertTrue("empty list is the no-mapping signal", bulk.get(key).isEmpty());

		assertFalse("and it agrees with the singular probe", mgr().hostNameAndIpMappingExists(host.getId()));
		assertTrue(mgr().getIpAddress("unmapped.example.com").isEmpty());
	}

	/**
	 * An id with no row is absent from the map. The single row getHostAddress
	 * reports the same condition by throwing, so this is the one place the bulk
	 * form deliberately differs and callers decide what to do.
	 */
	@Test
	public void testUnknownIdIsAbsentWhereSingularThrows() throws TskCoreException {
		HostAddress present = name("present.example.com");
		long missingId = 999_999_999L;

		Map<HostAddress, List<HostAddress>> bulk
				= mgr().getHostAddressMappings(Arrays.asList(present.getId(), missingId));

		assertEquals("only the row that exists comes back", 1, bulk.size());
		assertEquals(present.getId(), bulk.keySet().iterator().next().getId());

		try {
			mgr().getHostAddress(missingId);
			fail("the single row form is expected to throw for a missing id");
		} catch (TskCoreException expected) {
			// the documented difference
		}
	}

	/**
	 * Duplicate ids must not blow up the map build, and the degenerate inputs
	 * must short circuit rather than issue SQL.
	 */
	@Test
	public void testDuplicateAndDegenerateInput() throws TskCoreException {
		HostAddress host = name("dupes.example.com");
		HostAddress addr = ip("198.51.100.7");
		mapNameToIp(host, addr);

		Map<HostAddress, List<HostAddress>> bulk = mgr().getHostAddressMappings(
				Arrays.asList(host.getId(), host.getId(), host.getId()));

		assertEquals("duplicates collapse", 1, bulk.size());
		assertEquals("and do not duplicate the mapped ips", 1, bulk.values().iterator().next().size());

		assertTrue(mgr().getHostAddressMappings(Collections.emptyList()).isEmpty());
		assertTrue(mgr().getHostAddresses(HostAddressType.DNS_AUTO, Collections.emptyList()).isEmpty());

		try {
			mgr().getHostAddressMappings(null);
			fail("null input is expected to throw");
		} catch (TskCoreException expected) {
		}
		try {
			mgr().getHostAddresses(HostAddressType.DNS_AUTO, null);
			fail("null input is expected to throw");
		} catch (TskCoreException expected) {
		}
	}

	/**
	 * A DNS_AUTO batch resolves per address, so one call has to cope with IPV4
	 * and IPV6 rows at once, and must agree with the singular lookup for each.
	 */
	@Test
	public void testDnsAutoBatchSpansIpv4AndIpv6() throws TskCoreException {
		HostAddress v4 = ip("203.0.113.9");
		HostAddress v6 = ip("2001:db8::8a2e:370:7334");

		assertEquals(HostAddressType.IPV4, v4.getAddressType());
		assertEquals(HostAddressType.IPV6, v6.getAddressType());

		List<String> lookups = Arrays.asList("203.0.113.9", "2001:db8::8a2e:370:7334");
		Map<String, HostAddress> bulk = mgr().getHostAddresses(HostAddressType.DNS_AUTO, lookups);

		assertEquals(2, bulk.size());
		for (String lookup : lookups) {
			HostAddress singular = mgr().getHostAddress(HostAddressType.DNS_AUTO, lookup).orElse(null);
			assertNotNull("singular finds " + lookup, singular);
			assertEquals("bulk must agree with the singular for " + lookup, singular, bulk.get(lookup));
		}
	}

	/**
	 * Addresses are stored normalized and lower cased. The bulk form has to
	 * apply the same transform for matching, but key the result by whatever the
	 * caller handed in so callers never replicate normalization.
	 */
	@Test
	public void testKeyedByCallerStringNotStoredForm() throws TskCoreException {
		HostAddress host = name("MixedCase.Example.COM");

		String asSupplied = "MIXEDCASE.EXAMPLE.com";
		Map<String, HostAddress> bulk = mgr().getHostAddresses(HostAddressType.HOSTNAME, Arrays.asList(asSupplied));

		assertEquals(1, bulk.size());
		assertTrue("keyed by the caller's string", bulk.containsKey(asSupplied));
		assertEquals(host.getId(), bulk.get(asSupplied).getId());
		assertEquals("and agrees with the singular",
				mgr().getHostAddress(HostAddressType.HOSTNAME, asSupplied).orElse(null), bulk.get(asSupplied));
	}

	/**
	 * On SQLite the ids are split into chunks. Every chunk's rows have to end up
	 * in the returned map.
	 */
	@Test
	public void testChunkBoundaryIsMerged() throws TskCoreException {
		List<Long> ids = new ArrayList<>(CHUNK_CROSSING_COUNT);
		Set<Long> mappedIds = new HashSet<>();
		for (int i = 0; i < CHUNK_CROSSING_COUNT; i++) {
			HostAddress host = name("chunk-" + i + ".example.com");
			ids.add(host.getId());
			// Map a slice of them so both the mapped and unmapped shapes cross the boundary.
			if (i % 100 == 0) {
				mapNameToIp(host, ip("10.10." + (i / 256) + "." + (i % 256)));
				mappedIds.add(host.getId());
			}
		}

		Map<HostAddress, List<HostAddress>> bulk = mgr().getHostAddressMappings(ids);

		assertEquals("every id across every chunk comes back", CHUNK_CROSSING_COUNT, bulk.size());
		Set<Long> returnedIds = bulk.keySet().stream().map(HostAddress::getId).collect(Collectors.toSet());
		assertEquals(new HashSet<>(ids), returnedIds);

		for (Map.Entry<HostAddress, List<HostAddress>> entry : bulk.entrySet()) {
			boolean expectedMapped = mappedIds.contains(entry.getKey().getId());
			assertEquals("mapping state survives chunking for " + entry.getKey().getAddress(),
					expectedMapped, !entry.getValue().isEmpty());
			assertEquals("and agrees with the singular probe",
					mgr().hostNameAndIpMappingExists(entry.getKey().getId()), !entry.getValue().isEmpty());
		}
	}

	/**
	 * The whole point of the bulk form: looping the singulars over a mixed batch
	 * and calling the bulk form once must produce the same answer.
	 */
	@Test
	public void testBulkMatchesLoopedSingularsOverMixedBatch() throws TskCoreException {
		List<HostAddress> hosts = new ArrayList<>();
		for (int i = 0; i < 25; i++) {
			HostAddress host = name("mixed-" + i + ".example.com");
			hosts.add(host);
			if (i % 3 == 0) {
				mapNameToIp(host, ip("172.16.0." + i));
			}
			if (i % 5 == 0) {
				mapNameToIp(host, ip("172.17.0." + i));
			}
		}

		List<Long> ids = hosts.stream().map(HostAddress::getId).collect(Collectors.toList());

		Map<Long, List<HostAddress>> mappedIpsById = new HashMap<>();
		mgr().getHostAddressMappings(ids).forEach((address, ips) -> mappedIpsById.put(address.getId(), ips));
		Map<Long, HostAddress> addressById = addressesById(ids);

		for (HostAddress host : hosts) {
			Set<Long> expectedIps = mgr().getIpAddress(host.getAddress()).stream()
					.map(HostAddress::getId).collect(Collectors.toSet());
			Set<Long> actualIps = mappedIpsById.getOrDefault(host.getId(), Collections.emptyList()).stream()
					.map(HostAddress::getId).collect(Collectors.toSet());
			assertEquals("mapped ips for " + host.getAddress(), expectedIps, actualIps);

			assertEquals("address record for " + host.getAddress(),
					mgr().getHostAddress(host.getId()), addressById.get(host.getId()));
			assertEquals("mapping state for " + host.getAddress(),
					mgr().hostNameAndIpMappingExists(host.getId()), !actualIps.isEmpty());
		}
	}
}
