/*
 * SleuthKit Java Bindings
 *
 * Copyright 2020 Basis Technology Corp.
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

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to represent a file repository.
 */
public class FileRepository {
	
	private final static String FILE_PATH = "v1/files/";
	private final FileRepositorySettings settings;
	private final String fileDownloadFolder;
	
	private static FileRepository instance;

	/**
     * Create the file repository.
     *
     * @param settings          The file repository settings
     * @param fileDownloadPath  The temporary folder to download files to from the repository
     */
	private FileRepository(FileRepositorySettings settings, String fileDownloadPath) {
		this.settings = settings;
		this.fileDownloadFolder = fileDownloadPath;
	}
	
	/**
     * Initializes the file repository.
     *
     * @param settings          The file repository settings
     * @param fileDownloadPath  The temporary folder to download files to from the repository
     */	
	public static synchronized void initialize(FileRepositorySettings settings, String fileDownloadPath) {
		instance = new FileRepository(settings, fileDownloadPath);
	}
	
	/**
     * De-initializes the file repository.
     */	
	public static synchronized void deinitialize() {
		instance = null;
	}
	
	/**
     * Gets the instance of the file repository.
	 * 
	 * @return The instance of the file repository. Will be null if not initialized.
     */	
	public static synchronized FileRepository getInstance() {
		return instance;
	}
	
	/**
     * Download a file from the file repository.
     *
     * @param abstractFile The file being downloaded. 
	 * 
	 * @return The downloaded file.
	 * 
	 * @throws TskCoreException
     */
	public File downloadFromFileRepository(AbstractFile abstractFile) throws TskCoreException {

		if (! abstractFile.getFileLocation().equals(TskData.FileLocation.REPOSITORY)) {
			throw new TskCoreException("File with object ID " + abstractFile.getId() + " is not stored in the file repository");
		}
		
		if (abstractFile.getSha256Hash() == null || abstractFile.getSha256Hash().isEmpty()) {
			throw new TskCoreException("File with object ID " + abstractFile.getId() + " has no SHA-256 hash and can not be downloaded");
		}
		
		// Download the file if it's not already there.
		String targetPath = Paths.get(fileDownloadFolder, abstractFile.getSha256Hash()).toString();
		if ( ! new File(targetPath).exists()) {
			downloadFile(abstractFile, targetPath);
		}
		
		// Check that we got the file.
		File tempFile = new File(targetPath);
		if (tempFile.exists()) {
			System.out.println("Got file " + targetPath); // TODO REMOVE
			return tempFile;
		} else {
			throw new TskCoreException("Failed to download file with object ID " + abstractFile.getId() 
					+ " and SHA-256 hash " + abstractFile.getSha256Hash() + " from file repository");
		}
	}
	
	/**
     * Download the file.
     *
     * @param abstractFile The file being downloaded.
     * @param targetPath   The location to save the file to.
	 * 
	 * @throws TskCoreException
     */
	private void downloadFile(AbstractFile abstractFile, String targetPath) throws TskCoreException {		
		
		String url = "http://" + settings.getAddress() + ":" + settings.getPort() + "/" + FILE_PATH + abstractFile.getSha256Hash();
		
		List<String> command = new ArrayList<>();
		command.add("curl");
		command.add("-X");
		command.add("GET");
		command.add(url);
		command.add("-H");
		command.add("accept: */*");
		command.add("--output");
		command.add(targetPath);
		
		ProcessBuilder processBuilder = new ProcessBuilder(command).inheritIO();
		try {
			Process process = processBuilder.start();
			process.waitFor();
		} catch (IOException | InterruptedException ex) {
			throw new TskCoreException("Error downloading file with SHA-256 hash " + abstractFile.getSha256Hash() + " from file repository", ex);
		}
	}
	
	/**
     * Upload a given file to the file repository.
     *
     * @param filePath The path on disk to the file being uploaded.
     */
	public void uploadToFileRepository(String filePath) throws TskCoreException {
	
		File file = new File(filePath);
		if (! file.exists()) {
			throw new TskCoreException("Error uploading file " + filePath + " to file repository - file does not exist");
		}
		
		// Upload the file.
		uploadFile(file);
	}
	
	/**
     * Upload the file.
     *
     * @param file The file being uploaded.
	 * 
	 * @throws TskCoreException
     */	
	private void uploadFile(File file) throws TskCoreException {
		String url = "http://" + settings.getAddress() + ":" + settings.getPort() + "/" + FILE_PATH;
		
		// Example: curl -X POST "http://localhost:8080/api/files" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "file=@Report.xml"
		List<String> command = new ArrayList<>();
		command.add("curl");
		command.add("-X");
		command.add("POST");
		command.add(url);
		command.add("-H");
		command.add("accept: application/json");
		command.add("-H");
		command.add("Content-Type: multipart/form-data");
		command.add("-F");
		command.add("file=@" + file.getAbsolutePath());
		
		ProcessBuilder processBuilder = new ProcessBuilder(command).inheritIO();
		try {
			Process process = processBuilder.start();
			process.waitFor();
		} catch (IOException | InterruptedException ex) {
			throw new TskCoreException("Error saving file at " + file.getAbsolutePath() + " to file repository", ex);
		}	
	}	
		
	/**
	 * Utility class to hold the file repository server settings.
	 */
	static public class FileRepositorySettings {
		private final String address;
		private final String port;
		
		/**
		 * Create a FileRepositorySettings instance for the server.
		 * 
		 * @param address The IP address/hostname of the server.
		 * @param port    The port.
		 */
		public FileRepositorySettings(String address, String port) {
			this.address = address;
			this.port = port;
		}
		
		String getAddress() {
			return address;
		}
		
		String getPort() {
			return port;
		}
	}
}
