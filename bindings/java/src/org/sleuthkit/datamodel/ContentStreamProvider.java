/*
 * SleuthKit Java Bindings
 *
 * Copyright 2023 Basis Technology Corp.
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

/**
 * Custom provider for bytes of an abstract file.
 */
public interface ContentStreamProvider {

	/**
	 * Provides a content stream for a content object or empty if this provider
	 * has none to provide.
	 *
	 * @param content The content.
	 *
	 * @return The content stream or empty if no stream can be provided for this
	 *         content.
	 */
	Optional<ContentProviderStream> getContentStream(Content content) throws TskCoreException;
}
