/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import org.junit.AfterClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.BeforeClass;
/**
 *
 * @author smoss
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({org.sleuthkit.datamodel.TopDownTraversal.class})
public class DatamodeltestSuite {
	@BeforeClass
	public static void setUpClass() throws Exception{
		java.io.File imageStore=new java.io.File("TempStore.txt");
		imageStore.createNewFile();
		java.io.File results = new java.io.File("test"+java.io.File.separator+"Output"+java.io.File.separator+"Results");
		for(java.io.File del: results.listFiles())
		{
			del.delete();
		}
	}
	@AfterClass
	public static void tearDownClass() throws Exception {
		java.io.File imageStore=new java.io.File("TempStore.txt");
		List<String> files= new ArrayList<String>();
		Scanner inp = new Scanner(imageStore);
		while(inp.hasNextLine())
		{
			files.add(inp.nextLine());
		}
		inp.close();
		List<String> goldfs = new ArrayList<String>();
		for(String gold : files)
		{
			gold = gold.replace("_Results","_Standard");
			
			goldfs.add(gold);
		}
		String path="test"+java.io.File.separator+"Output"+java.io.File.separator;
		String origpath = path+"Gold"+java.io.File.separator;
		String revpath = path+"Results"+java.io.File.separator;
		try{
			for(int x=0; x<files.size(); x++)
			{
				String diff=DiffUtil.getDiff(origpath+goldfs.get(x), revpath+files.get(x), goldfs.get(x).replace(".txt",""));
				if(diff.equals(""))
				{
					long wait=System.currentTimeMillis();
					while((System.currentTimeMillis()-wait)<3000){}
					DiffUtil.emptyResults(revpath, files.get(x));
				}
			}
		}
		catch(Exception ex){
			System.out.println("FNF");
		}
		imageStore.delete();
	}
}
