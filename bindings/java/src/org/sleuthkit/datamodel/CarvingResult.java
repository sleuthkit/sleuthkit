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
 * A carving result consisting of a set of carved files and the image, volume,
 * or file system from which they were carved.
 */
public final class CarvingResult {

	private final Content carvedFilesParent;
	private final List<CarvedFile> carvedFiles;

	/**
	 * Constructs a carving result consisting of a set of carved files and the
	 * image from which they were carved.
	 *
	 *
	 * @param carvedFilesParent An image that is the parent of a set of carved
	 *                          files.
	 * @param carvedFiles       The carved files.
	 */
	public CarvingResult(Image carvedFilesParent, List<CarvedFile> carvedFiles) {
		this.carvedFilesParent = carvedFilesParent;
		this.carvedFiles = carvedFiles;
	}

	/**
	 * Constructs a carving result consisting of a set of carved files and the
	 * volume from which they were carved.
	 *
	 * @param carvedFilesParent A volume that is the parent of a set of carved
	 *                          files.
	 * @param carvedFiles       The carved files.
	 */
	public CarvingResult(FileSystem carvedFilesParent, List<CarvedFile> carvedFiles) {
		this.carvedFilesParent = carvedFilesParent;
		this.carvedFiles = carvedFiles;
	}

	/**
	 * Constructs a carving result consisting of a set of carved files and file
	 * system from which they were carved.
	 *
	 * @param carvedFilesParent A file system that is the parent of a set of
	 *                          carved files.
	 * @param carvedFiles       The carved files.
	 */
	public CarvingResult(Volume carvedFilesParent, List<CarvedFile> carvedFiles) {
		this.carvedFilesParent = carvedFilesParent;
		this.carvedFiles = carvedFiles;
	}

	/**
	 * Gets the parent of a set the carved files in a carving result.
	 *
	 * @return The carved files parent.
	 */
	final Content getCarvedFilesParent() {
		return carvedFilesParent;
	}

	/**
	 * Gets the set of carved files in a carving result.
	 *
	 * @return The carved files.
	 */
	final List<CarvedFile> getCarvedFiles() {
		return carvedFiles;
	}

	/**
	 * A file carved out of a parent image, volume, or file system.
	 */
	public static class CarvedFile {

		private final String name;
		private final long sizeInBytes;
		private final List<TskFileRange> layoutInParent;

		/**
		 * Constructs a file carved out of a parent image, volume, or file
		 * system.
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
		 * Gets the name of a carved file.
		 *
		 * @return The file name.
		 */
		final String getName() {
			return name;
		}

		/**
		 * Gets the size of a carved file.
		 *
		 * @return The size of the file in bytes.
		 */
		final long getSizeInBytes() {
			return sizeInBytes;
		}

		/**
		 * Gets the layout of the carved file within its parent image, voluem,
		 * or file system.
		 *
		 * @return A list of TskRange objects representing the layoput of the
		 *         carved file within its parent.
		 */
		final List<TskFileRange> getLayoutInParent() {
			return layoutInParent;
		}

	}

}
