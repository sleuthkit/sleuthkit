/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2016 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import java.util.List;

/**
 * A carving result consisting of a set of carved files and the parent content
 * (e.g., an unallocated space file or an image data source) from which the
 * files were carved.
 */
public final class CarvingResult {

	private final Content parent;
	private final List<CarvedFile> carvedFiles;

	/**
	 * Constructs a carving result consisting of a set of carved files and the
	 * parent content (e.g., an unallocated space file or an image data source)
	 * from which the files were carved.
	 *
	 * @param parent      The parent of a set of carved files.
	 * @param carvedFiles The carved files.
	 */
	public CarvingResult(Content parent, List<CarvedFile> carvedFiles) {
		this.parent = parent;
		this.carvedFiles = carvedFiles;
	}

	/**
	 * Gets the parent of the carved files in a carving result.
	 *
	 * @return The carved files parent.
	 */
	final Content getParent() {
		return parent;
	}

	/**
	 * Gets the carved files in a carving result.
	 *
	 * @return The carved files.
	 */
	final List<CarvedFile> getCarvedFiles() {
		return carvedFiles;
	}

	/**
	 * A file carved out of parent content (e.g., an unallocated space file or
	 * an image data source).
	 */
	public static class CarvedFile {

		private final String name;
		private final long sizeInBytes;
		private final List<TskFileRange> layoutInParent;

		/**
		 * Constructs a file carved out of parent content (e.g., an unallocated
		 * space file or an image data source).
		 *
		 * @param name           The name of the file.
		 * @param sizeInBytes    The size of the file in bytes.
		 * @param layoutInParent The layout of the file within the parent.
		 */
		public CarvedFile(String name, long sizeInBytes, List<TskFileRange> layoutInParent) {
			this.name = name;
			this.sizeInBytes = sizeInBytes;
			this.layoutInParent = layoutInParent;
		}

		/**
		 * Gets the name of the carved file.
		 *
		 * @return The file name.
		 */
		final String getName() {
			return name;
		}

		/**
		 * Gets the size of the carved file.
		 *
		 * @return The size of the file in bytes.
		 */
		final long getSizeInBytes() {
			return sizeInBytes;
		}

		/**
		 * Gets the layout of the carved file within its parent.
		 *
		 * @return A list of TskRange objects representing the layoput of the
		 *         carved file within its parent.
		 */
		final List<TskFileRange> getLayoutInParent() {
			return layoutInParent;
		}

	}

}
