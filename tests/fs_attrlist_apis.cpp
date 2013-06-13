/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2008-2011 Brian Carrier.  All Rights reserved
*
*
* This software is distributed under the Common Public License 1.0
*
*/

/* Test and compare the file attribute list apis */

#include "tsk/tsk_tools_i.h"

static char *s_root;



/* Verify that a specific attribute can be read from the file
* @param a_addr The metadata address of the file to analyze
* @param a_type Type that is known to be in file
* @returns 1 if a test failed
*/
static int
test_get_type(TSK_FS_INFO * a_fs, TSK_INUM_T a_addr,
    TSK_FS_ATTR_TYPE_ENUM a_type)
{
    TSK_FS_FILE *fs_file;

    // open the file
    fs_file = tsk_fs_file_open_meta(a_fs, NULL, a_addr);
    if (!fs_file) {
        fprintf(stderr, "Error opening file %" PRIuINUM " via meta\n",
            a_addr);
        tsk_error_print(stderr);
        return 1;
    }

    // verify the specified type can be opened
    const TSK_FS_ATTR *fs_attr =
        tsk_fs_file_attr_get_type(fs_file, a_type, 0, 0);
    if (!fs_attr) {
        fprintf(stderr,
            "Error getting specified attribute %d-X (no id) from %"
            PRIuINUM "\n", a_type, a_addr);
        tsk_error_print(stderr);
        return 1;
    }

    tsk_fs_file_close(fs_file);
    return 0;
}

/* Verify that all attributes can be accessed from both get_idx and get_type...
 * @param a_addr The metadata address of the file to analyze
 * @param a_len Expected number of attributes in file.
 * @returns 1 if a test failed
 */
static int
test_get_apis(TSK_FS_INFO * a_fs, TSK_INUM_T a_addr, int a_len)
{
    TSK_FS_FILE *fs_file;
    int retval = 0;

    // open the file
    fs_file = tsk_fs_file_open_meta(a_fs, NULL, a_addr);
    if (!fs_file) {
        fprintf(stderr, "Error opening file %" PRIuINUM " via meta\n",
            a_addr);
        tsk_error_print(stderr);
        return 1;
    }

    int len = tsk_fs_file_attr_getsize(fs_file);
    if (len != a_len) {
        fprintf(stderr,
            "%" PRIuINUM
            " attribute count diff from expected (%d vs %d)\n", a_addr,
            a_len, len);
        tsk_error_print(stderr);
        return 1;
    }

    for (int i = 0; i < len; i++) {

        // get the attribute by index
        const TSK_FS_ATTR *fs_attr = tsk_fs_file_attr_get_idx(fs_file, i);
        if (!fs_attr) {
            fprintf(stderr,
                "Error getting attribute %d from %" PRIuINUM "\n", i,
                a_addr);
            tsk_error_print(stderr);
            return 1;
        }

        // verify we can also get it via type / id
        const TSK_FS_ATTR *fs_attr2 =
            tsk_fs_file_attr_get_type(fs_file, fs_attr->type, fs_attr->id,
            1);
        if (!fs_attr2) {
            fprintf(stderr,
                "Error getting attribute %d-%d from %" PRIuINUM "\n",
                fs_attr->type, fs_attr->id, a_addr);
            tsk_error_print(stderr);
            return 1;
        }

        if ((fs_attr->type != fs_attr2->type)
            || (fs_attr->id != fs_attr2->id)) {
            fprintf(stderr,
                "Attribute from get_type not expected %d-%d vs %d-%d from %"
                PRIuINUM "\n", fs_attr->type, fs_attr->id, fs_attr2->type,
                fs_attr2->id, a_addr);
            tsk_error_print(stderr);
            return 1;
        }

        if (fs_attr != fs_attr2) {
            fprintf(stderr,
                "Attribute from get_type not same addr as original %lu vs %lu from %"
                PRIuINUM "\n", (long) fs_attr, (long) fs_attr2, a_addr);
            tsk_error_print(stderr);
            return 1;
        }

        // verify we also get something via only type
        fs_attr2 = tsk_fs_file_attr_get_type(fs_file, fs_attr->type, 0, 0);
        if (!fs_attr2) {
            fprintf(stderr,
                "Error getting attribute %d (no id) from %" PRIuINUM "\n",
                fs_attr->type, a_addr);
            tsk_error_print(stderr);
            return 1;
        }

        if (fs_attr->type != fs_attr2->type) {
            fprintf(stderr,
                "Attribute from get_type (no id) not expected %d vs %d from %"
                PRIuINUM "\n", fs_attr->type, fs_attr2->type, a_addr);
            tsk_error_print(stderr);
            return 1;
        }

        // Try with a "random" ID: Note this atribute could actually exist...
        fs_attr2 =
            tsk_fs_file_attr_get_type(fs_file, fs_attr->type, 0xfd, 1);
        if (fs_attr2) {
            fprintf(stderr,
                "Got unexpected attribute %d-0xfd (random ID) from %"
                PRIuINUM "\n", fs_attr->type, a_addr);
            tsk_error_print(stderr);
            return 1;
        }
        else if (tsk_error_get_errno() != TSK_ERR_FS_ATTR_NOTFOUND) {
            fprintf(stderr,
                "Unexpected error code %x from getting %d-0xfd (random ID) from %"
                PRIuINUM "\n", (int)tsk_error_get_errno(), fs_attr->type, a_addr);
            tsk_error_print(stderr);
            return 1;
        }
        tsk_error_reset();

        // Try with a "random" type Note this atribute could actually exist...
        fs_attr2 =
            tsk_fs_file_attr_get_type(fs_file,
            (TSK_FS_ATTR_TYPE_ENUM) (fs_attr->type + 37), 0, 0);
        if (fs_attr2) {
            fprintf(stderr,
                "Got unexpected attribute %d-X (random type, no id) from %"
                PRIuINUM "\n", fs_attr->type + 37, a_addr);
            tsk_error_print(stderr);
            return 1;
        }
        else if (tsk_error_get_errno() != TSK_ERR_FS_ATTR_NOTFOUND) {
            fprintf(stderr,
                "Unexpected error code %x from getting %d-X (random type, no id) from %"
                PRIuINUM "\n", (int)tsk_error_get_errno(), fs_attr->type, a_addr);
            tsk_error_print(stderr);
            return 1;
        }
        tsk_error_reset();

    }

    tsk_fs_file_close(fs_file);

    return retval;
}



int
test_fat12()
{
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    const char *tname = "fat12.dd";
    char fname[512];

    snprintf(fname, 512, "%s/fat12.dd", s_root);
    if ((img = tsk_img_open_sing((const TSK_TCHAR *)fname, (TSK_IMG_TYPE_ENUM) 0, 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        return 1;
    }

    if ((fs = tsk_fs_open_img(img, 0, (TSK_FS_TYPE_ENUM) 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        return 1;
    }

    // verify the APIs get teh same for file 47
    if (test_get_apis(fs, 47, 1)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }

    // verify the one attribte is the expected type
    if (test_get_type(fs, 47, TSK_FS_ATTR_TYPE_DEFAULT)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }

    tsk_fs_close(fs);
    tsk_img_close(img);
    return 0;
}


static int
test_ntfs_fe()
{
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    const char *tname = "fe_test_1-NTFS";
    char fname[512];

    snprintf(fname, 512, "%s/fe_test_1.img", s_root);
    if ((img = tsk_img_open_sing((const TSK_TCHAR *)fname, (TSK_IMG_TYPE_ENUM) 0, 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        return 1;
    }

    if ((fs = tsk_fs_open_img(img, 32256, (TSK_FS_TYPE_ENUM) 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        return 1;
    }

    // Verify the APIS get the same and that they are the expected type
    if (test_get_apis(fs, 35, 3)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 35, TSK_FS_ATTR_TYPE_NTFS_SI)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 35, TSK_FS_ATTR_TYPE_NTFS_FNAME)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 35, TSK_FS_ATTR_TYPE_NTFS_DATA)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }


    if (test_get_apis(fs, 9, 7)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 9, TSK_FS_ATTR_TYPE_NTFS_SI)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 9, TSK_FS_ATTR_TYPE_NTFS_FNAME)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 9, TSK_FS_ATTR_TYPE_NTFS_DATA)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 9, TSK_FS_ATTR_TYPE_NTFS_IDXROOT)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 9, TSK_FS_ATTR_TYPE_NTFS_IDXALLOC)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }
    else if (test_get_type(fs, 9, TSK_FS_ATTR_TYPE_NTFS_BITMAP)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }

    tsk_fs_close(fs);
    tsk_img_close(img);
    return 0;
}



int
main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "missing image root directory\n");
        return 1;
    }
    s_root = argv[1];

    if (test_fat12())
        return 1;
    if (test_ntfs_fe())
        return 1;

    printf("Tests Passed\n");
    return 0;
}
