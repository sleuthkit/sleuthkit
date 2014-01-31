/**
 * Java plug-in for JPEG extractor. This plug-in gateways to the "exif" plug-in two ways.
 * Way #1 - from the command line, using the standard DGI interface.
 * Way #2 - using the JVM interface.
 */

import java.io.*;
import java.util.regex.*;
import java.lang.Runtime;

class jpeg_extract {
    static String processExifOutput(String s){
	String[] parts = s.split("\t");
	String name  = parts[0].replace(" ","-").replace(":","-").replace("(","-").replace(")","-");
        String value = "";
        if (parts.length > 1){
           value = parts[1]; 
        }
	return name + ": " + value;
    }
    /**
     * process FN with exif and return a string of name: value\r
     */
    static String process(String fn){
	StringBuilder sb = new StringBuilder();
	try {
	    ProcessBuilder pb = new ProcessBuilder("exif","-m",fn);
	    Process p = pb.start();
	    InputStream is = p.getInputStream(); // "data piped from the standard output stream of the process"
	    InputStreamReader isr = new InputStreamReader(is);
	    BufferedReader br = new BufferedReader(isr);
	    while(true){
		String s = br.readLine();
		if(s==null) break;
		sb.append(processExifOutput(s));
		sb.append("\n");
	    }
	    br.close();
	    is.close();
	    
	} catch (java.io.IOException e){
	    e.printStackTrace();
	}
	return sb.toString();
    }

    public static void main(String[] args){
	//System.out.print(process(args[0]));
        if (args.length >= 1){
            System.out.print(process(args[0]));
        }else{
             System.out.println("Usage: jpeg_extract filename.***, legal extensions are .jpeg, .jpg");
             System.exit(0);
        }//end else 
    }
}
