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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbConnection;

/**
 *
 */
public class FileRepositoryManager {
	
	private final static String FILE_PATH = "v1/files/";
	private final SleuthkitCase skCase;
	private FileRepositorySettings settings;
	private String fileDownloadFolder;
	
	// Create an unitialized file repository
	FileRepositoryManager(SleuthkitCase skCase) {
		this.skCase = skCase;
		settings = null;
		fileDownloadFolder = "";
	}
	
	public synchronized void initializeSettings(FileRepositorySettings settings, String fileDownloadPath) {
		this.settings = settings;
		this.fileDownloadFolder = fileDownloadPath;
	}
	
	/**
	 * Check whether the file repository has been initialized.
	 */
	public synchronized boolean isEnabled() {
		return settings != null;
	}
	

	public boolean caseUsesFileRepository() throws TskCoreException {
		skCase.acquireSingleUserCaseReadLock();
		try (CaseDbConnection connection = skCase.getConnection();
			Statement statement = connection.createStatement();
			ResultSet rs = connection.executeQuery(statement, "SELECT COUNT(*) as count FROM tsk_files WHERE location=" + TskData.FileLocation.REPOSITORY.getValue());) {
			int count = 0;
			if (rs.next()) {
				count = rs.getInt("count");
			}
			return count > 0;
		} catch (SQLException ex) {
			throw new TskCoreException("Error querying case database for files stored in repository", ex);
		} finally {
			skCase.releaseSingleUserCaseReadLock();
		}
	}
	
	private String getFilePath(AbstractFile abstractFile) {
		return Paths.get(fileDownloadFolder, abstractFile.getSha256Hash()).toString();
	}
	
	public File loadFromFileRepository(AbstractFile abstractFile) throws TskCoreException {
		if (!isEnabled()) {
			throw new TskCoreException("File repository is not enabled");
		}
		
		if (! abstractFile.getFileLocation().equals(TskData.FileLocation.REPOSITORY)) {
			throw new TskCoreException("File with object ID " + abstractFile.getId() + " is not stored in the file repository");
		}
		
		if (abstractFile.getSha256Hash() == null || abstractFile.getSha256Hash().isEmpty()) {
			throw new TskCoreException("File with object ID " + abstractFile.getId() + " has no SHA-256 hash and can not be downloaded");
		}
		
		// Download the file if it's not already there.
		String downloadPath = getFilePath(abstractFile);
		if ( ! new File(downloadPath).exists()) {
			downloadFileFromFileService(abstractFile, downloadPath);
		}
		
		// Check that we got the file.
		File tempFile = new File(downloadPath);
		if (tempFile.exists()) {
			return tempFile;
		} else {
			throw new TskCoreException("Failed to download file with object ID " + abstractFile.getId() 
					+ " and SHA-256 hash " + abstractFile.getSha256Hash() + " from file repository");
		}
	}
	
	private String makeUrl(AbstractFile abstractFile) {
		return "http://" + settings.getAddress() + ":" + settings.getPort() + "/" + FILE_PATH + abstractFile.getSha256Hash();
	}
	
	private void downloadFileFromFileService(AbstractFile abstractFile, String downloadPath) throws TskCoreException {		
		
		List<String> command = new ArrayList<>();
		command.add("curl");
		command.add("-X");
		command.add("GET");
		command.add(makeUrl(abstractFile));
		command.add("-H");
		command.add("accept: */*");
		command.add("--output");
		command.add(downloadPath);
		
		ProcessBuilder processBuilder = new ProcessBuilder(command).inheritIO();
		try {
			Process process = processBuilder.start();
			process.waitFor();
		} catch (IOException | InterruptedException ex) {
			throw new TskCoreException("Error downloading file with SHA-256 hash " + abstractFile.getSha256Hash() + " from file repository", ex);
		}
	}
	
	/**
	 * @param abstractFile 
	 * @param trans
	 */
	public void saveToFileRepository(AbstractFile abstractFile) throws TskCoreException {
		
		if (! isEnabled()) {
			throw new TskCoreException("File repository is not enabled");
		}
		
		// Make sure the SHA-256 hash has been calculated
		if (abstractFile.getSha256Hash() == null || abstractFile.getSha256Hash().isEmpty()) {
			HashUtility.calculateHashes(abstractFile, Arrays.asList(HashUtility.HashType.SHA256));
			abstractFile.save();
		}
		
		String filePath = "";
		if (abstractFile.getLocalPath() == null || abstractFile.getLocalPath().isEmpty()) {
			try {
				filePath = extractFileToDisk(abstractFile);
			} catch (IOException ex) {
				throw new TskCoreException("Error writing temporary file to disk", ex);
			}
		} else {
			filePath = abstractFile.getLocalAbsPath();
		}
		
		// Save the abstractFile data
		saveLocalFileToFileService(filePath);
	}
	
	public void updateFileToUseFileRepository(AbstractFile abstractFile, SleuthkitCase.CaseDbTransaction trans)throws TskCoreException {
		
		// Update the file table entry
		try {
			SleuthkitCase.CaseDbConnection connection = trans.getConnection();
			
			// Change the location to REPOSITORY
			String updateLocation = "UPDATE tsk_files SET location = ? WHERE obj_id = ?"; // NON-NLS
			PreparedStatement statement = connection.getPreparedStatement(updateLocation, Statement.NO_GENERATED_KEYS);	
			statement.clearParameters();
			statement.setLong(1, TskData.FileLocation.REPOSITORY.getValue());
			statement.setLong(2, abstractFile.getId());
			connection.executeUpdate(statement);

			// Remove entry for this file in tsk_files_path (if it exists)
			String removePath = "DELETE FROM tsk_files_path WHERE obj_id = ?"; // NON-NLS
			statement = connection.getPreparedStatement(removePath, Statement.NO_GENERATED_KEYS);
			statement.clearParameters();
			statement.setLong(1, abstractFile.getId());
			connection.executeUpdate(statement);

		} catch (SQLException ex) {
			throw new TskCoreException("Error updating database for move to file repository", ex);
		}
	}
	
	private void saveLocalFileToFileService(String pathToFile) throws TskCoreException {
		File file = new File(pathToFile);
		
		// curl -X POST "http://localhost:8080/api/files" -H "accept: application/json" -H "Content-Type: multipart/form-data" -F "file=@Report.xml"
		List<String> command = new ArrayList<>();
		command.add("curl");
		command.add("-X");
		command.add("POST");
		command.add("http://localhost:8080/v1/files");
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
			throw new TskCoreException("Error saving file at " + pathToFile + " to file repository", ex);
		}	
	}
	
	private String extractFileToDisk(AbstractFile abstractFile) throws IOException {
		String extractedPath = getFilePath(abstractFile);
		
		InputStream in = new ReadContentInputStream(abstractFile);
		try (FileOutputStream out = new FileOutputStream(extractedPath, false)) {
            byte[] buffer = new byte[0x2000];
            int len = in.read(buffer);
            while (len != -1) {
                out.write(buffer, 0, len);
                len = in.read(buffer);
            }
		} catch (FileNotFoundException ex) {
			throw new IOException("Error exporting file with object ID " + abstractFile.getId() + " to " + extractedPath, ex);
        } finally {
            in.close();
        }
		return extractedPath;
	}
	
		
	static public class FileRepositorySettings {
		String address;
		String port;
		
		public FileRepositorySettings(String address, String port) {
			this.address = address;
			this.port = port;
		}
		
		public String getAddress() {
			return address;
		}
		
		public String getPort() {
			return port;
		}
	}
}
