#include <stdio.h>
#include "arff.h"

#include <stdlib.h>

/**
 * this test program tests the ARFF output system.
 * That's all it does.
 */

int main(int argc,char **argv)
{
    printf("ARFF Test Program\n");

    arff a("test relation");

    a.add_comment("This is a test file");
    a.add_comment("Just a test");
    a.add_attribute("blue",arff::NUMERIC);
    a.add_attribute("green",arff::NUMERIC);
    a.add_attribute("name",arff::STRING);
    a.add_attribute("mydate",arff::STRING);
    a.new_row();
    a.add_value("blue",1);
    a.add_value("green",10);
    a.add_value("name","Administrator");
    a.new_row();
    a.add_value("green",20);
    a.add_value("blue",2);
    a.add_value("name","All Users");
    a.add_value("mydate","2002:10:18 11:21:00");
    a.new_row();
    a.add_value("blue",3);
    a.add_value("mydate", "2007-01-30T13:50:00Z");
    a.set_outfile(stdout);

    a.new_row();
    a.add_value("name","Simson");
    a.write();

    /* TODO: For our test program, check to make sure that the types
       of all of the attributes were properly identified. */

    exit(0);
}

