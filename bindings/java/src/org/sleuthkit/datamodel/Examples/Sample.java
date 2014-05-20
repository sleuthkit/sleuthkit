/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.sleuthkit.datamodel.Examples;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;
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
			AddImageProcess process = sk.makeAddImageProcess(timezone, true, false);
			ArrayList<String> paths = new ArrayList<String>();
			paths.add(imagePath);
			try {
				process.run(paths.toArray(new String[paths.size()]));
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
			List<AbstractFile> files = sk.findAllFilesWhere("name like '%.txt'");
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
