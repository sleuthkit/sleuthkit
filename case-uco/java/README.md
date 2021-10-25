# Sleuth Kit CASE JSON Support
This package supports exporting Sleuth Kit DataModel objects to Cyber-investigation Analysis Standard Expression (CASE). 

Clients will interface with the CaseUcoExporter class. This class contains methods to export most DataModel objects present in the Sleuth Kit Java Bindings. 

**DISCLAIMER**: All API's in this package are subject to change.

# Building the JAR file
To build the JAR file, simply run '**ant jar**' in the case-uco/java folder. Alternatively, you can add the code to a NetBeans project and build using the regular 'build' action.

# Configuration Properties
Some behavior of the exporter can be configured via a Java Properties object. See the table below for available configuration properties.

| Parameter | Description | Default |
| :---: | :---: | :---: |
| exporter.relationships.includeParentChild | Include or exclude parent-child relationships from the CASE output. By default, this class will export all parent-child relationships present in The Sleuth Kit DataModel. Volume System to Volume would be an example of such a relationship. If your use case requires exporting only the Volume, this configuration property will toggle that behavior. | true |    


# Design Basics #
This JAR is (as far as we know) primarily used by a Autopsy report module.  The report module drives the process and uses the CaseUcoExporter class (in this JAR) to convert TSK data model objects to the JSON-LD CASE/UCO data. 

The JAR contains POJO classes that represent the CASE/UCO objects.  CaseUcoExporter will populate the POJO classes and they then get serialized via GSON.  As much as possible, the class and member variable names in the POJOs line up with the CASE/UCO names (except for prefixes that contain colons). 

This code does not have the ability to import CASE/UCO and generate TSK objects.  It is export only. 
