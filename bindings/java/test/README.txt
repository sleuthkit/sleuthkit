This file describes the tests. There are several test that are run, including:
- TopDown that tests getChildren() on each object.
- BottomUp that tests getParent() on each object.
- Sequentail that tests accessing random objects.
- CPPvsJava that verifies that the C++ output is the same as Java.

Not all test compare with a gold standard. Refer to each class for details. The following names are used in the output folder though:
- _TD: TopDown data that contains metadata about each file reached from getChildren(). This is checked in.
- _Seq: Sequentail test data that contains metadata about each file. This is checked in. 
- _CPP: Body file format of files. This is not checked in.
- _BU: BottomUp data that contains paths to root from leaf nodes (i.e. files). This is not checked in. 
