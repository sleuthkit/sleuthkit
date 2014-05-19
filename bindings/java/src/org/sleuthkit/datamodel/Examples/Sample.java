/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.sleuthkit.datamodel.Examples;
import java.util.List;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
/**
 *
 */
public class Sample {
	public static void run(String imagePath) {
		try {
		SleuthkitCase sk = SleuthkitCase.newCase(imagePath + ".db");
		
		String timezone = "";
		sk.makeAddImageProcess(timezone, true, false);
		
		List<Image> images = sk.getImages();
		
		for (Image image : images) {
			for (Content content : image.getChildren()) {
				System.out.println(content.getName());
				}
			}
		
		List<AbstractFile> files = sk.findFiles(null, "*.txt");
		
		for (AbstractFile file : files) {
			System.out.println(file.getLocalAbsPath());
			}
		
		} catch (TskCoreException e) {
			System.out.println("Exception caught: " + e.getMessage());
		}		
	}
	
	public static void main(String[] args) {
		Sample.run("C:\\Users\\ajacks\\TSK\\xp-sp3-v4\\xp-sp3-v4.001");
	}
}
