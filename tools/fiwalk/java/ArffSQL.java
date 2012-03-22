import java.io.*;
import java.sql.*;
import weka.core.Attribute;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.Utils;

// See http://www.ling.ohio-state.edu/~jansche/src/weka/c45/ExportC45.java


// upload an ARFF system to 

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

public class ArffSQL {
    public static void usage(){
	System.err.println("Usage java ArffTest database table filename.arff ; use - for stdin");
	System.exit(-1);
    }

    public static Connection mysql_connect() {
        String MP = System.getenv("DOMEX_MYSQL_PASSWORD");
	if(MP==null) throw new RuntimeException("DOMEX_MYSQL_PASSWORD not set");

        String username = System.getenv("DOMEX_MYSQL_USERNAME");
	if(username==null) throw new RuntimeException("DOMEX_MYSQL_USERNAME not set");

        System.out.printf("Mysql username/password is %s/%s%n",username,MP);

        try {
            Class.forName("com.mysql.jdbc.Driver");
            String url = "jdbc:mysql://" + System.getenv("DOMEX_MYSQL_HOSTNAME")+":3306/mysql";
            Connection con = DriverManager.getConnection(url,username,MP);
	    return con;
        } catch( Exception e ) {
            e.printStackTrace();
	    return null;
        }//end catch 
    }

    /** for each attribute in dataset d, add the field to the current database
     * of Connection con if the field is not there...
     */
    public static void add_missing_fields(MyDataset d,Connection con,String table){
	java.util.HashSet<String> fields = new java.util.HashSet<String>();
	rs = stmt.executeQuery("describe "+table);
	while(rs.next()){
	    String fname = rs.getString("Field");
	    System.out.println(fname);
	    fields.add(fname);
	}
	System.out.println("fields: "+fields);
    }
	

    public void process(String db,String table,String fn){
	mysql_connect();

	try {
	    Reader in = new FileReader(fn);
	    MyDataset d = new MyDataset(in);
	    Connection con = mysql_connect();
	    Statement stmt = con.createStatement();
            ResultSet rs = stmt.executeQuery("use "+db);

	    add_missing_fields(d,con);
            rs.close();
	    con.close();
	} catch (FileNotFoundException e){
	    System.err.printf("%s: file not found",fn);
	} catch (IOException e){
	    System.err.printf("%s: IOException reading file",fn);
	} catch (java.sql.SQLException e){
	    e.printStackTrace();
	}
    }

    public static void main(String[] args) {

	if(args.length < 3){
		usage();
	}
	ArffSQL worker = new ArffSQL();
	worker.process(args[0],args[1],args[2]);
    }
}
