import java.io.*;
import weka.core.Attribute;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.Utils;

// See http://www.ling.ohio-state.edu/~jansche/src/weka/c45/ExportC45.java


class MyDataset extends Instances {
    public MyDataset(Reader reader) throws IOException{
	super(reader);
    }
    public void info(PrintStream out) {
	out.printf("Number of Attributes: %d%n",numAttributes());
	out.printf("Class Index: %d%n",classIndex());
	out.printf("Relation Name: %s%n",relationName());
	out.printf("Names: %n");
	for(int i=0;i<numAttributes();i++){
	    Attribute a = attribute(i);
	    out.printf("  %s : %n",a.name());
	}
	out.printf("%n");
	out.printf("Values: %n");
	for(int i=0;i<numInstances();i++){
	    Instance inst = instance(i);
	    for(int j=0;j<numAttributes();j++){
		if(j>0) out.printf(", ");
		if(inst.isMissing(j)){
		    out.printf("? ");
		} else if(inst.attribute(j).isNumeric()){
		    double g = inst.value(j);
		    if(Math.floor(g)==g) out.printf("%d ",(int)g);
		    else out.printf("%f ",g);
		} else {
		    out.printf("%s ",inst.stringValue(j));
		}
	    }
	    out.printf("%n");
	}
	out.printf("%n");
    }
}

public class ArffTest {
    public static void usage(){
	System.err.println("Usage java ArffTest <*.arff> ; use - for stdin");
	System.exit(-1);
    }
    public static void process(String fn){
	try {
	    Reader in = new FileReader(fn);
	    MyDataset d = new MyDataset(in);
	    d.info(System.out);
	} catch (FileNotFoundException e){
	    System.err.printf("%s: file not found",fn);
	} catch (IOException e){
	    System.err.printf("%s: IOException reading file",fn);
	}
	
    }
    public static void main(String[] args) {
	    if(args.length < 1){
		usage();
	    }
	    for(String fn :args){
		process(fn);
	    }
	}
}
