# Sleuth Kit CASE JSON LD Support
This package supports exporting Sleuth Kit DataModel objects to Cyber-investigation Analysis Standard Expression (CASE). 

Clients will interface with the CaseUcoExporter class. This class contains methods to export most DataModel objects present in the Sleuth Kit Java Bindings. 

# Building the JAR file
To build the JAR file, simply run '**mvn clean install**' in the case-uco/java folder. Alternatively, you can add the code to a NetBeans project and build using the regular 'build' action.

# Configuration Properties
Some behavior of the exporter can be configured via a Java Properties object. Below is a table of available configuration properties.

| Parameter | Description | Default |
| :---: | :---: | :---: |
| exporter.relationships.includeParentChild | Include or exclude parent-child relationships from the CASE output. By default, this class will export all parent-child relationships present in The Sleuth Kit DataModel. Volume System to Volume would be example of such a relationship. If your use case requires exporting only the Volume, this configuration property will toggle that behavior. | true |    
