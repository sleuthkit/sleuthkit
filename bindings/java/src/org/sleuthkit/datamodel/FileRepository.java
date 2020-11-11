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
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Class to represent a file repository.
 */
public class FileRepository {
	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	private static final Logger logger = Logger.getLogger(FileRepository.class.getName());
	private static FileRepositoryErrorHandler errorHandler;
	
	private final static String FILE_PATH = "v1/files/";
	private final FileRepositorySettings settings;
	private final File fileDownloadFolder;
	
	private static FileRepository instance;

	/**
     * Create the file repository.
     *
     * @param settings          The file repository settings
     * @param fileDownloadPath  The temporary folder to download files to from the repository
     */
	private FileRepository(FileRepositorySettings settings, File fileDownloadPath) {
		this.settings = settings;
		this.fileDownloadFolder = fileDownloadPath;
	}
	
	/**
     * Initializes the file repository.
     *
     * @param settings          The file repository settings
     * @param fileDownloadPath  The temporary folder to download files to from the repository
     */	
	public static synchronized void initialize(FileRepositorySettings settings, File fileDownloadPath) {
		// If the download path is changing, delete any files in the old one
		if ((instance != null) && (instance.fileDownloadFolder != null)
				&& ( ! instance.fileDownloadFolder.equals(fileDownloadPath))) {
			deleteDownloadFolder(instance.fileDownloadFolder);
		}
		instance = new FileRepository(settings, fileDownloadPath);
	}
	
	/**
     * De-initializes the file repository.
     */	
	public static synchronized void deinitialize() {
		if (instance != null) {
			// Delete the temp folder
			deleteDownloadFolder(instance.fileDownloadFolder);
		}
		
		instance = null;
	}
	
	/**
	 * Check if the file repository is enabled.
	 * 
	 * @return true if enabled, false otherwise.
	 */
	public static boolean isEnabled() {
		return instance != null;
	}
	
	/**
	 * Set the error handling callback.
	 * 
	 * @param handler The error handler.
	 */
	public static synchronized void setErrorHandler(FileRepositoryErrorHandler handler) {
		errorHandler = handler;
	}
	
	/**
	 * Report an error to the user.
	 * The idea is to use this for cases where it's a user error that may be able
	 * to be corrected through changing the repository settings.
	 * 
	 * @param errorTitle The title for the error display.
	 * @param errorStr   The error message.
	 */
	private static synchronized void reportError(String errorTitle, String errorStr) {
		if (errorHandler != null) {
			errorHandler.displayErrorToUser(errorTitle, errorStr);
		}
	}
	
	/**
	 * Delete the folder of downloaded files.
	 */
	private static synchronized void deleteDownloadFolder(File dirPath) {
        if (dirPath.isDirectory() == false || dirPath.exists() == false) {
            return;
        }

        File[] files = dirPath.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteDownloadFolder(file);
                } else {
                    if (file.delete() == false) {
                        logger.log(Level.WARNING, "Failed to delete file {0}", file.getPath()); //NON-NLS
                    }
                }
            }
        }
        if (dirPath.delete() == false) {
            logger.log(Level.WARNING, "Failed to delete the empty directory at {0}", dirPath.getPath()); //NON-NLS
        }
	}
	
	/**
     * Download a file from the file repository.
	 * The caller must ensure that this is not called on the same file multiple times concurrently. 
     *
     * @param abstractFile The file being downloaded. 
	 * 
	 * @return The downloaded file.
	 * 
	 * @throws TskCoreException
     */
	public static synchronized File downloadFromFileRepository(AbstractFile abstractFile) throws TskCoreException {

		if (instance == null) {
			String title = BUNDLE.getString("FileRepository.downloadError.title.text");
			String msg = BUNDLE.getString("FileRepository.notEnabled.msg.text");
			reportError(title, msg);
			throw new TskCoreException("File repository is not enabled");
		}
		
		if (! abstractFile.getFileLocation().equals(TskData.FileLocation.REPOSITORY)) {
			throw new TskCoreException("File with object ID " + abstractFile.getId() + " is not stored in the file repository");
		}
		
		if (abstractFile.getSha256Hash() == null || abstractFile.getSha256Hash().isEmpty()) {
			throw new TskCoreException("File with object ID " + abstractFile.getId() + " has no SHA-256 hash and can not be downloaded");
		}
		
		// Download the file if it's not already there.
		String targetPath = Paths.get(instance.fileDownloadFolder.getAbsolutePath(), abstractFile.getSha256Hash()).toString();
		if ( ! new File(targetPath).exists()) {
			instance.downloadFile(abstractFile, targetPath);
		}
		
		// Check that we got the file.
		File tempFile = new File(targetPath);
		if (tempFile.exists()) {
			return tempFile;
		} else {
			String title = BUNDLE.getString("FileRepository.downloadError.title.text");
			String msg = MessageFormat.format(BUNDLE.getString("FileRepository.downloadError.msg.text"), abstractFile.getId(), abstractFile.getSha256Hash());
			reportError(title, msg);
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
		} catch (IOException ex) {
			String title = BUNDLE.getString("FileRepository.downloadError.title.text");
			String msg = MessageFormat.format(BUNDLE.getString("FileRepository.downloadError.msg.text"), abstractFile.getId(), abstractFile.getSha256Hash());
			reportError(title, msg);
			throw new TskCoreException("Error downloading file with SHA-256 hash " + abstractFile.getSha256Hash() + " from file repository", ex);
		} catch (InterruptedException ex) {
			throw new TskCoreException("Interrupted while downloading file with SHA-256 hash " + abstractFile.getSha256Hash() + " from file repository", ex);
		}
	}
	
	/**
     * Upload a given file to the file repository.
     *
     * @param filePath The path on disk to the file being uploaded.
	 * 
	 * @throws TskCoreException
     */
	public static synchronized void uploadToFileRepository(String filePath) throws TskCoreException {
	
		if (instance == null) {
			throw new TskCoreException("File repository is not enabled");
		}
		
		File file = new File(filePath);
		if (! file.exists()) {
			throw new TskCoreException("Error uploading file " + filePath + " to file repository - file does not exist");
		}
		
		// Upload the file.
		instance.uploadFile(file);
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
	
	/**
	 * Callback class to use for error reporting. 
	 */
	public interface FileRepositoryErrorHandler {
		/**
		 * Handles displaying an error message to the user (if appropriate).
		 * 
		 * @param title The title for the error display.
		 * @param error The more detailed error message to display.
		 */
		void displayErrorToUser(String title, String error);
	}
}
