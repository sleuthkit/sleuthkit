/*
 * The Sleuth Kit
 *
 *
 * Copyright (c) 2010 Basis Technology Corp.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <libtsk.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>



int main(int argc, char **argv) {
	// Get the top level suite from the registry
	  CppUnit::Test *suite = CppUnit::TestFactoryRegistry::getRegistry().makeTest();

	  // Adds the test to the list of test to run
	  CppUnit::TextUi::TestRunner runner;
	  runner.addTest( suite );

	  // Change the default outputter to a compiler error format outputter
	  runner.setOutputter( new CppUnit::CompilerOutputter( &runner.result(),
	                                                       std::cerr ) );
	  // Run the tests.
	  bool wasSuccessful = runner.run();

	  // Return error code 1 if the one of test failed.
	  return wasSuccessful ? 0 : 1;
}




