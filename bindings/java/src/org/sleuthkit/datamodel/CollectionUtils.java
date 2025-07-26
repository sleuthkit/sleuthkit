/*
 * Sleuth Kit Data Model
 *
 * Copyright 2017 Basis Technology Corp.
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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;

/**
 * Static utilities for dealing with Collections. At some point this could be
 * replaced with apache commons or guava...
 */
final class CollectionUtils {

	@SuppressWarnings("unchecked")
	static <T> HashSet<T> hashSetOf(T... values) {
		return new HashSet<>(Arrays.asList(values));
	}

	static <T> boolean isNotEmpty(Collection<T> collection) {
		return collection.isEmpty() == false;
	}

	private CollectionUtils() {
	}
}
