/**
 * fiwalk.cpp:
 * File and Inode Walk.
 *
 * This application uses SleuthKit to generate a report of all of the files
 * and orphaned inodes found in a disk image. It can optionally compute the
 * MD5 of any objects, save those objects into a directory, or both.
 *
 * Algorithm:
 * 1 - Find all of the partitions on the disk.
 * 2 - For each partition, walk the files.
 * 3 - For each file, print the requested information.
 * 4 - For each partition, walk the indoes
 * 5 - For each inode, print the requested information.
 *
 * @author Simson Garfinkel
 *
 *
 * The software provided here is released by the Naval Postgraduate
 * School, an agency of the U.S. Department of Navy.  The software
 * bears no warranty, either expressed or implied. NPS does not assume
 * legal liability nor responsibility for a User's use of the software
 * or the results of such use.
 *
 * Please note that within the United States, copyright protection,
 * under Section 105 of the United States Code, Title 17, is not
 * available for any work of the United States Government and/or for
 * any works created by United States Government employees. User
 * acknowledges that this software contains work which was created by
 * NPS government employees and is therefore in the public domain and
 * not subject to copyright.
 */

/* config.h must be first */
#include "tsk/tsk_tools_i.h"

#include <stdio.h>
#include "fiwalk.h"

extern "C" int main(int argc, char * const *argv)
{
    return fiwalk_main(argc, argv);
}
