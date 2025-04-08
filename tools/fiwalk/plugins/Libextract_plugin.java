
/**
 * @author james migletz
 * Template based on JPEG_extractor.java written by
 * Simson Garfinkel
 * 
 * Filename: Libextract_Plugin.java
 *
 * Description: Java plug-in for libextractor.
 * This plug-in gateways to the "libextractor" plug-in 
 * through the command line, using the standard DGI interface.
 */

import java.io.*;
import java.util.regex.*;
import java.lang.Runtime;

class Libextract_plugin {
    static String processLibextractOutput(String s){
        String[] parts = s.split(" -");

	try {
	    String name  = parts[0].replace(" ","-");
	    String value = parts[1];
	    return name + ": " + value;
	} catch (ArrayIndexOutOfBoundsException e){
	    return null;
	}
    }
    /**
     * process FN with libextractor and return a string of name: value\r
     */
    static String process(String fn){     
        
        StringBuilder sb = new StringBuilder();
        try {
            ProcessBuilder pb = new ProcessBuilder("extract",fn);
            Process p = pb.start();
            InputStream is = p.getInputStream(); // "data piped from the standard output stream of the process"
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            while(true){
                String s = br.readLine();
                if(s==null) break;	// end of file
		String a = processLibextractOutput(s);
		if(a!=null){
		    sb.append(a);
		    sb.append("\n");
		}
            }
            br.close();
            is.close();
            
        } catch (java.io.IOException e){
            e.printStackTrace();
        }
        return sb.toString();
    }

    public static void main(String[] args){
        System.out.print(process(args[0]));
    }
}

