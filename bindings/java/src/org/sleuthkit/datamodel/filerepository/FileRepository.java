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
package org.sleuthkit.datamodel.filerepository;

import com.google.gson.Gson;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.TskData;

/**
 * Class to represent a file repository.
 */
public class FileRepository {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.filerepository.Bundle");
	private static final int MAX_BULK_QUERY_SIZE = 500;
	private final static String V1_FILES_TEMPLATE = "http://%s:%s/v1/files/";
	
	private final Gson gson;
	private final FileRepositorySettings settings;
	
	private static FileRepositoryErrorHandler errorHandler;
	private static FileRepository instance;

	/**
	 * Create the file repository.
	 *
	 * @param settings         The file repository settings
	 * @param fileDownloadPath The temporary folder to download files to from
	 *                         the repository
	 */
	FileRepository(FileRepositorySettings settings) {
		this.settings = settings;
		this.gson = new Gson();
	}

	/**
	 * Initializes the file repository.
	 *
	 * @param settings The file repository settings
	 */
	public static synchronized void initialize(FileRepositorySettings settings) {
		instance = new FileRepository(settings);
	}

	/**
	 * De-initializes the file repository.
	 */
	public static synchronized void deinitialize() {
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
	 * Report an error to the user. The idea is to use this for cases where it's
	 * a user error that may be able to be corrected through changing the
	 * repository settings.
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
	 * Download a file's data from the file repository. The resulting stream
	 * must be closed and it should be read as soon as possible.
	 *
	 * @param abstractFile The file to be downloaded.
	 *
	 * @return The file contents, as a stream.
	 *
	 * @throws org.sleuthkit.datamodel.filerepository.FileRepositoryException
	 * @throws java.io.IOException
	 *
	 */
	public static synchronized InputStream download(AbstractFile abstractFile) throws FileRepositoryException, IOException {
		// Preconditions
		ensureInstanceIsEnabled();
		ensureNonEmptySHA256(abstractFile);
		ensureFileLocationIsRemote(abstractFile);

		return instance.sendDownloadRequest(abstractFile.getSha256Hash());
	}

	/**
	 * Private function to perform file download.
	 */
	private InputStream sendDownloadRequest(String SHA256) throws IOException, FileRepositoryException {
		final CloseableHttpClient httpClient = HttpClients.createDefault();
		final String downloadURL = settings.createBaseURL(V1_FILES_TEMPLATE) + SHA256;

		final HttpGet downloadRequest = new HttpGet(downloadURL);
		final CloseableHttpResponse response = httpClient.execute(downloadRequest);
		final int statusCode = response.getStatusLine().getStatusCode();

		if (statusCode != HttpStatus.SC_OK) {
			FileRepositoryException repoEx = null;
			try {
				final String title = BUNDLE.getString("FileRepository.error.title.text");
				final String message = BUNDLE.getString("FileRepository.downloadError.msg.text");
				reportError(title, message);
				final String errorMessage = extractErrorMessage(response);
				repoEx = new FileRepositoryException(String.format("Request "
						+ "failed with the following response body %s. Please "
						+ "check the file repository logs for more information.", errorMessage));
			} finally {
				try {
					response.close();
				} catch (IOException ex) {
					// Best effort
					if (repoEx != null) {
						repoEx.addSuppressed(ex);
					}
				}

				try {
					httpClient.close();
				} catch (IOException ex) {
					// Best effort
					if (repoEx != null) {
						repoEx.addSuppressed(ex);
					}
				}
			}

			throw repoEx;
		}

		// Client and response will close once the stream has been
		// consumed and closed by the client.
		return new HTTPInputStream(httpClient, response);
	}

	/**
	 * Uploads a stream of data to the file repository.
	 *
	 *
	 * @param stream Arbitrary data to store in this file repository.
	 *
	 * @throws java.io.IOException
	 * @throws org.sleuthkit.datamodel.filerepository.FileRepositoryException
	 */
	public static synchronized void upload(InputStream stream) throws IOException, FileRepositoryException {
		// Preconditions
		ensureInstanceIsEnabled();

		instance.sendUploadRequest(stream);
	}

	/**
	 * Private function to perform file upload.
	 */
	private void sendUploadRequest(InputStream stream) throws IOException, FileRepositoryException {
		try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
			final String uploadURL = settings.createBaseURL(V1_FILES_TEMPLATE);

			// Flush the stream to a local temp file for transport.
			final Path temp = Paths.get(System.getProperty("java.io.tmpdir"), UUID.randomUUID().toString());
			Files.copy(stream, temp);

			final HttpEntity fileUpload = MultipartEntityBuilder.create()
					.addBinaryBody("file", temp.toFile())
					.build();
			final HttpUriRequest postRequest = RequestBuilder.post(uploadURL)
					.setEntity(fileUpload)
					.build();

			try (CloseableHttpResponse response = httpClient.execute(postRequest)) {
				checkSuccess(response);
			} catch (IOException | FileRepositoryException ex) {
				try {
					Files.delete(temp);
				} catch (IOException deleteEx) {
					ex.addSuppressed(deleteEx);
				}
				throw ex;
			} finally {
				try {
					Files.delete(temp);
				} catch (IOException ex) {
					// Do nothing, best effort.
				}
			}
		}
	}

	/**
	 * Checks if many abstract files are stored within this file repository.
	 * This API is tolerant of files without SHA-256 values, as opposed to its
	 * overridden counterpart, which will throw an exception if not present.
	 *
	 * @param files Files to test
	 *
	 * @return An object encapsulating the response for each file.
	 *
	 * @throws java.io.IOException
	 * @throws org.sleuthkit.datamodel.filerepository.FileRepositoryException
	 */
	public static synchronized BulkExistenceResult exists(List<AbstractFile> files) throws IOException, FileRepositoryException {
		// Preconditions
		ensureInstanceIsEnabled();
		ensureBulkQuerySize(files);

		return instance.sendMultiExistenceQuery(new ExistenceQuery(files));
	}

	/**
	 * Private function to perform the bulk existence query.
	 */
	private BulkExistenceResult sendMultiExistenceQuery(ExistenceQuery query) throws IOException, FileRepositoryException {
		try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
			final String existsURL = settings.createBaseURL(V1_FILES_TEMPLATE) + "exists";
			final String jsonString = gson.toJson(query);
			final StringEntity jsonEntity = new StringEntity(jsonString, StandardCharsets.UTF_8);

			final HttpPut bulkExistsPost = new HttpPut(existsURL);
			bulkExistsPost.setEntity(jsonEntity);
			bulkExistsPost.setHeader("Accept", "application/json");
			bulkExistsPost.setHeader("Content-type", "application/json");

			try (CloseableHttpResponse response = httpClient.execute(bulkExistsPost)) {
				checkSuccess(response);

				final HttpEntity entity = response.getEntity();
				final ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
				entity.writeTo(byteOutputStream);
				final String jsonBody = new String(byteOutputStream.toByteArray(), StandardCharsets.UTF_8);
				return gson.fromJson(jsonBody, BulkExistenceResult.class);
			}
		}
	}

	/**
	 * Checks if the abstract file is stored within this file repository.
	 *
	 * @param file Abstract file to query
	 *
	 * @return True/False
	 *
	 * @throws IOException
	 * @throws FileRepositoryException
	 */
	public static synchronized boolean exists(AbstractFile file) throws IOException, FileRepositoryException {
		// Preconditions
		ensureInstanceIsEnabled();
		ensureNonEmptySHA256(file);

		if (!file.getFileLocation().equals(TskData.FileLocation.REPOSITORY)) {
			return false;
		}

		return instance.sendSingularExistenceQuery(file.getSha256Hash());
	}

	/**
	 * Private function to perform the existence query.
	 */
	private boolean sendSingularExistenceQuery(String SHA256) throws IOException, FileRepositoryException {
		try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
			final String existsURL = settings.createBaseURL(V1_FILES_TEMPLATE) + SHA256;

			final HttpHead request = new HttpHead(existsURL);

			try (CloseableHttpResponse response = httpClient.execute(request)) {
				final int statusCode = response.getStatusLine().getStatusCode();
				switch (statusCode) {
					case HttpStatus.SC_OK:
						return true;
					case HttpStatus.SC_NOT_FOUND:
						return false;
					default:
						throw new FileRepositoryException(String.format("Unexpected "
								+ "response code. Expected 200 or 404, but instead got %d. "
								+ "Please check the file repository logs for more information.", statusCode));
				}
			}
		}
	}

	/**
	 * Prevents a query if the file is not remote.
	 */
	private static void ensureFileLocationIsRemote(AbstractFile abstractFile) throws FileRepositoryException {
		if (!abstractFile.getFileLocation().equals(TskData.FileLocation.REPOSITORY)) {
			throw new FileRepositoryException("File with object ID " + abstractFile.getId() + " is not stored in the file repository");
		}
	}

	/**
	 * Prevents a query for a file with no SHA-256.
	 */
	private static void ensureNonEmptySHA256(AbstractFile abstractFile) throws FileRepositoryException {
		if (abstractFile.getSha256Hash() == null || abstractFile.getSha256Hash().isEmpty()) {
			throw new FileRepositoryException("File with object ID " + abstractFile.getId() + " has no SHA-256 hash.");
		}
	}

	/**
	 * Ensures the instance is enabled, notifying users otherwise.
	 */
	private static void ensureInstanceIsEnabled() throws FileRepositoryException {
		if (!isEnabled()) {
			final String title = BUNDLE.getString("FileRepository.error.title.text");
			final String msg = BUNDLE.getString("FileRepository.notEnabled.msg.text");
			reportError(title, msg);
			throw new FileRepositoryException("File repository is not enabled");
		}
	}

	/**
	 * Prevents a request from being made if it exceeds the maximum threshold
	 * for a bulk query.
	 */
	private static void ensureBulkQuerySize(List<AbstractFile> files) throws FileRepositoryException {
		if (files.size() > MAX_BULK_QUERY_SIZE) {
			throw new FileRepositoryException(String.format("Exceeds the allowable "
					+ "threshold (%d) for a single request.", MAX_BULK_QUERY_SIZE));
		}
	}

	/**
	 * Checks the status code of the response and throws a templated exception
	 * if it's not the expected 200 code.
	 */
	private static void checkSuccess(CloseableHttpResponse response) throws FileRepositoryException, IOException {
		final int statusCode = response.getStatusLine().getStatusCode();

		if (statusCode != HttpStatus.SC_OK) {
			final String errorMessage = extractErrorMessage(response);
			throw new FileRepositoryException(String.format("Request failed with "
					+ "the following response body %s. Please check the file "
					+ "repository logs for more information.", errorMessage));
		}
	}

	/**
	 * Extracts the entire response body as a plain string.
	 */
	private static String extractErrorMessage(CloseableHttpResponse response) throws IOException {
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(
				response.getEntity().getContent(), StandardCharsets.UTF_8))) {
			return reader.lines().collect(Collectors.joining("\n"));
		}
	}

	/**
	 * Query object to be serialized by GSON and sent as a payload to the bulk
	 * exists endpoint.
	 */
	private static class ExistenceQuery {

		private final List<String> files;

		ExistenceQuery(List<AbstractFile> absFiles) {
			files = new ArrayList<>();
			for (AbstractFile file : absFiles) {
				if (file.getSha256Hash() != null && !file.getSha256Hash().isEmpty()) {
					files.add(file.getSha256Hash());
				}
			}
		}
	}

	/**
	 * Streams data over a HTTP connection.
	 */
	private static class HTTPInputStream extends FilterInputStream {

		private final CloseableHttpResponse response;
		private final CloseableHttpClient client;

		HTTPInputStream(CloseableHttpClient client, CloseableHttpResponse response) throws IOException {
			super(response.getEntity().getContent());
			this.response = response;
			this.client = client;
		}

		@Override
		public void close() throws IOException {
			super.close();
			response.close();
			client.close();
		}
	}
}
