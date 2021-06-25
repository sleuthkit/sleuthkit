/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.caseuco;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 *
 * Runs all regression tests and contains utility methods for the tests The
 * default ant target sets properties for the various folders.
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
    FacetDeserializerTests.class
})
public class TestSuite {

}
