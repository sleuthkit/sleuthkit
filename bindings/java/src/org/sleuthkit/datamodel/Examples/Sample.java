/*
 * Sleuth Kit Data Model
 *
 * Copyright 2012-2018 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel.Examples;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.SleuthkitJNI.CaseDbHandle.AddImageProcess;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskDataException;

/**
 *
 */
public class Sample {

	public static void run(String imagePath) {
		try {
			SleuthkitCase sk = SleuthkitCase.newCase(imagePath + ".db");

			// initialize the case with an image
			String timezone = "";
			AddImageProcess process = sk.makeAddImageProcess(timezone, true, false, "");
			ArrayList<String> paths = new ArrayList<String>();
			paths.add(imagePath);
			try {
				process.run(UUID.randomUUID().toString(), paths.toArray(new String[paths.size()]), 0);
			} catch (TskDataException ex) {
				Logger.getLogger(Sample.class.getName()).log(Level.SEVERE, null, ex);
			}
			process.commit();

			// print out all the images found, and their children
			List<Image> images = sk.getImages();
			for (Image image : images) {
				System.out.println("Found image: " + image.getName());
				System.out.println("There are " + image.getChildren().size() + " children.");
				for (Content content : image.getChildren()) {
					System.out.println('"' + content.getName() + '"' + " is a child of " + image.getName());
				}
			}

			// print out all .txt files found
			List<AbstractFile> files = sk.findAllFilesWhere("LOWER(name) LIKE LOWER('%.txt')");
			for (AbstractFile file : files) {
				System.out.println("Found text file: " + file.getName());
			}

		} catch (TskCoreException e) {
			System.out.println("Exception caught: " + e.getMessage());
			Sample.usage(e.getMessage());

		}
	}

	public static void usage(String error) {
		System.out.println("Usage: ant -Dimage:{image string} run-sample");
		if (error.contains("deleted first")) {
			System.out.println("A database for the image already exists. Delete it to run this sample again.");
		} else if (error.contains("unable to open database")) {
			System.out.println("Image must be encapsulated by double quotes. Ex: ant -Dimage=\"C:\\Users\\You\\image.E01\" run-sample");
		}
	}

	public static void main(String[] args) {
		Sample.run(args[0]);
	}
}
