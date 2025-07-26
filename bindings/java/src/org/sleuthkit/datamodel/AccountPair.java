/*
 * SleuthKit Java Bindings
 *
 * Copyright 2018 Basis Technology Corp.
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

/**
 * Class representing an unordered pair of account device instances. <a,b> is
 * same as <b,a>. First and second are used to distinguish the two accounts, but
 * do not imply an order.
 */
public final class AccountPair {

	private final AccountDeviceInstance account1;
	private final AccountDeviceInstance account2;

	/**
	 * Get the first AccountDeviceInstance. First doesn't imply order and is
	 * simply used to distinguish the two accounts.
	 *
	 * @return The first AccountDeviceInstance.
	 */
	public AccountDeviceInstance getFirst() {
		return account1;
	}

	/**
	 * Get the second AccountDeviceInstance. Second doesn't imply order and is
	 * simply used to distinguish the two accounts.
	 *
	 * @return The second AccountDeviceInstance.
	 */
	public AccountDeviceInstance getSecond() {
		return account2;
	}

	AccountPair(AccountDeviceInstance account1, AccountDeviceInstance account2) {
		this.account1 = account1;
		this.account2 = account2;
	}

	@Override
	public int hashCode() {
		return account1.hashCode() + account2.hashCode();
	}

	@Override
	public boolean equals(Object other) {
		if (other == this) {
			return true;
		}
		if (!(other instanceof AccountPair)) {
			return false;
		}
		AccountPair otherPair = (AccountPair) other;
		return (account1.equals(otherPair.account1) && account2.equals(otherPair.account2))
				|| (account1.equals(otherPair.account2) && account2.equals(otherPair.account1));
	}
}
