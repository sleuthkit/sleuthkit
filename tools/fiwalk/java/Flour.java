import java.io.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;
import org.apache.xerces.parsers.SAXParser;

public class Flour extends DefaultHandler {

  float amount = 0;

  public void startElement(String namespaceURI, String localName,
                           String qName, Attributes atts) {
    if (namespaceURI.equals("http://recipes.org") && localName.equals("ingredient")) {
       String n = atts.getValue("","name");
       if (n.equals("flour")) {
         String a = atts.getValue("","amount"); // assume 'amount' exists
         amount = amount + Float.valueOf(a).floatValue();
       }
    }
  }

  public static void main(String[] args) {
    Flour f = new Flour();
    SAXParser p = new SAXParser();
    p.setContentHandler(f);
    try { p.parse(args[0]); } 
    catch (Exception e) {e.printStackTrace();}
    System.out.println(f.amount);
  }
}
