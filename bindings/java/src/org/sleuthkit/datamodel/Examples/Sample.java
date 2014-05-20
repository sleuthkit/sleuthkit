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
			
			List<Image> images = sk.getImages();
			System.out.println("images size is " + images.size());
			for (Image image : images) {
				System.out.println("Found image: " + image.getName());
				for (Content content : image.getChildren()) {
					System.out.println(content.getName());
					}
			
				}
						
			List<AbstractFile> files;			
			files = sk.findAllFilesWhere("name like '%.txt'");

			
			for (AbstractFile file : files) {
							System.out.println(file.getName());
						}
			
		} catch (TskCoreException e) {
			System.out.println("Exception caught: " + e.getMessage());
		}
	}

	public static void main(String[] args) {
		Sample.run("C:\\Users\\ajacks\\TSK\\nps-2008-jean\\nps-2008-jean.E01");
	}
}
