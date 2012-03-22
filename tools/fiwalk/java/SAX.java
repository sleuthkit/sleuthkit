import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;
import org.apache.xerces.parsers.SAXParser;
public class SAX extends DefaultHandler
{    
      int tagCount = 0;

      public void startElement(String uri, String localName, 
         String rawName, Attributes attributes) 
      {
            if (rawName.equals("servlet")) {
               tagCount++;
            } 
      }

      public void endDocument() 
      {
            System.out.println("There are " + tagCount + 
                " <servlet> elements.");
      }

      public static void main(String[] args) 
      {
            try {
                  SAX SAXHandler = new SAX();

                  SAXParser parser = new SAXParser();
                  parser.setContentHandler(SAXHandler);
                  parser.setErrorHandler(SAXHandler);
                  parser.parse(args[0]);
            }
                  catch (Exception ex) {
                        System.out.println(ex);
                  }
      }
}

