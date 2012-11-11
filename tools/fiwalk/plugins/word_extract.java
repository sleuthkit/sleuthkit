
/**
 * @author james migletz
 * Template based on JPEG_extract.java written by
 * Simson Garfinkel
 * 
 * Filename: word_extract.java
 * Date: 2 May 08
 *
 * Description: Java plug-in for wvSummary.
 * This plug-in gateways to the "wvSummary" plug-in 
 * through the command line, using the standard DGI interface.
 */

import java.io.*;
import java.util.regex.*;
import java.lang.Runtime;

class word_extract {
    static String processWvOutput(String s){
        String[] parts = s.split(" =");
	if(parts.length!=2){
	    System.err.println("Invalid response from wv: "+s);
	    return null;
	}

        String name  = parts[0].replace(" ","-").replace(":","-");
        String trimmedName = name.trim();
	if (trimmedName.length()==0) return null; 
        String value = parts[1].replace('"', ' ');
        return trimmedName + ":" + value;
    }
    /**
     * process FN with wvSummary and return a string of name: value\r
     */
    static String process(String fn){     
        
        StringBuilder sb = new StringBuilder();
        try {
            ProcessBuilder pb = new ProcessBuilder("wvSummary",fn);
            Process p = pb.start();   // "data piped from the standard output stream of the process"
            InputStream is = p.getInputStream(); 
            InputStreamReader isr = new InputStreamReader(is);
            BufferedReader br = new BufferedReader(isr);
            Boolean flag = false;
            while(true){
                String s = br.readLine();
                /*check to see if line read was first line.
                  if it is the first line, 
                     1. prepend "Filename =" to it
                     2. remove "Metadata for" 
                     3. set flag to true for subsequent reads
                */
                if (s==null) break;	// end of input
                if (!flag){
                   s = "Filename = " + s.substring(13, s.length()-1);
                   flag = true;
                }
		String a = processWvOutput(s);
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
        if (args.length >= 1){
            System.out.print(process(args[0]));
        }else{
             System.out.println("Usage: word_extract filename.***, legal extensions are .doc, .xls, .ppt");
             System.exit(0);
        }//end else 
    }
}

