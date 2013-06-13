/*
* The Sleuth Kit 
*
*
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2008-2011 Brian Carrier.  All Rights reserved
*
* This software is distributed under the Common Public License 1.0
*/

/*
 * this is a test file for The Sleuth Kit.  It tests the various
 * read API functions.  It uses "file_walk" for specific files and then
 * verifies the data passed to the callback using the fs_file_read()
 * function, fs_read() function, and img_read() function.  Note that
 * not all files can be tested with the latter options because the file
 * could be sparse or compressed. 
 */
#include "tsk/tsk_tools_i.h"

static TSK_FS_FILE *s_file2;
static TSK_OFF_T s_off;
static char *s_buf;
static char *s_root;


/* Callback that is used to do the testing */

static TSK_WALK_RET_ENUM
fw_action1(TSK_FS_FILE * a_fs_file, TSK_OFF_T a_off, TSK_DADDR_T a_addr,
    char *a_buf, size_t a_size, TSK_FS_BLOCK_FLAG_ENUM a_flags,
    void *a_ptr)
{
    TSK_OFF_T tmp_off;
    ssize_t cnt;
    size_t tmp_len;
    TSK_FS_INFO *fs = a_fs_file->fs_info;

    // verify teh offset passed is what we expected
    if (a_off != s_off) {
        fprintf(stderr,
            "offset passed in callback (%" PRIuOFF
            ") diff from internal off (%" PRIuOFF ")\n", a_off, s_off);
    }

    /* The first set of tests is for the file_read API.  We seek
     * to a "random" place to move around any caches, adn then read
     * from the same offset that this call is from.  We compare
     * the buffers. */

    // pick a random place and length
    tmp_off = (s_off * 4 + 1372) % s_file2->meta->size;
    if (s_file2->meta->size - tmp_off > fs->block_size)
        tmp_len = fs->block_size;
    else
        tmp_len = s_file2->meta->size - tmp_off;

    cnt =
        tsk_fs_file_read(s_file2, tmp_off, s_buf, tmp_len,
        (TSK_FS_FILE_READ_FLAG_ENUM) 0);
    if (cnt != (ssize_t) tmp_len) {
        fprintf(stderr,
            "Error reading random offset %" PRIuOFF " in file sized %"
            PRIuOFF " (%zd vs %zd)\n", tmp_off, s_file2->meta->size, cnt,
            tmp_len);
        tsk_error_print(stderr);
        return TSK_WALK_ERROR;
    }

    // now read from the real offset and compare with what we were passed
    if (a_size > fs->block_size)
        tmp_len = fs->block_size;
    else
        tmp_len = a_size;

    cnt =
        tsk_fs_file_read(s_file2, s_off, s_buf, tmp_len,
        (TSK_FS_FILE_READ_FLAG_ENUM) 0);
    if (cnt != (ssize_t) tmp_len) {
        fprintf(stderr,
            "Error reading file offset %" PRIuOFF " in file sized %"
            PRIuOFF "\n", s_off, s_file2->meta->size);
        tsk_error_print(stderr);
        return TSK_WALK_ERROR;
    }

    if (memcmp(s_buf, a_buf, a_size)) {
        fprintf(stderr,
            "Buffers at offset %" PRIuOFF " in file %" PRIuINUM
            " are different\n", s_off, s_file2->meta->addr);
        return TSK_WALK_ERROR;
    }
    s_off += a_size;

    /* IF the block we were passed is RAW (not BAD, resident, compressed etc.,
     * then read using the fs_read() API 
     */
    if (a_flags & TSK_FS_BLOCK_FLAG_RAW) {
        tmp_off = (a_addr * 42 + 82) % fs->last_block;

        cnt = tsk_fs_read_block(fs, tmp_off, s_buf, fs->block_size);
        if (cnt != (ssize_t) fs->block_size) {
            fprintf(stderr,
                "Error reading random block %" PRIuOFF " in file system\n",
                tmp_off);
            tsk_error_print(stderr);
            return TSK_WALK_ERROR;
        }

        cnt = tsk_fs_read_block(fs, a_addr, s_buf, fs->block_size);
        if (cnt != (ssize_t) fs->block_size) {
            fprintf(stderr, "Error reading block %" PRIuOFF "\n", a_addr);
            tsk_error_print(stderr);
            return TSK_WALK_ERROR;
        }

        // compare
        if (memcmp(s_buf, a_buf, a_size)) {
            fprintf(stderr,
                "Buffers at block addr %" PRIuOFF " in file %" PRIuINUM
                " are different\n", a_addr, s_file2->meta->addr);
            return TSK_WALK_ERROR;
        }

        /* Now we also read using the img_read() API, just because we can */
        cnt = tsk_fs_read_block(fs, tmp_off, s_buf, fs->block_size);
        if (cnt != (ssize_t) fs->block_size) {
            fprintf(stderr,
                "Error reading random block %" PRIuOFF " in file system\n",
                tmp_off);
            tsk_error_print(stderr);
            return TSK_WALK_ERROR;
        }

        // get the offset into the image
        tmp_off = a_addr * fs->block_size + fs->offset;
        cnt = tsk_img_read(fs->img_info, tmp_off, s_buf, fs->block_size);
        if (cnt != (ssize_t) fs->block_size) {
            fprintf(stderr,
                "Error reading image offset %" PRIuOFF " in image\n",
                tmp_off);
            tsk_error_print(stderr);
            return TSK_WALK_ERROR;
        }

        // compare
        if (memcmp(s_buf, a_buf, a_size)) {
            fprintf(stderr,
                "Buffers at image offset  %" PRIuOFF " in file %" PRIuINUM
                " are different\n", tmp_off, s_file2->meta->addr);
            return TSK_WALK_ERROR;
        }

    }

    return TSK_WALK_CONT;
}


int
testfile(TSK_FS_INFO * a_fs, TSK_INUM_T a_inum)
{
    TSK_FS_FILE *file1 = NULL;

    if ((s_buf = (char *) malloc(a_fs->block_size)) == NULL) {
        fprintf(stderr, "Error allocating  memory\n");
        return 1;
    }

    file1 = tsk_fs_file_open_meta(a_fs, NULL, a_inum);
    if (file1 == NULL) {
        fprintf(stderr, "Error opening inode %" PRIuINUM "\n", a_inum);
        return 1;
    }

    s_file2 = tsk_fs_file_open_meta(a_fs, NULL, a_inum);
    if (s_file2 == NULL) {
        fprintf(stderr, "Error opening inode %" PRIuINUM "\n", a_inum);
        return 1;
    }

    s_off = 0;
    if (tsk_fs_file_walk(file1, (TSK_FS_FILE_WALK_FLAG_ENUM) 0,
            fw_action1, NULL)) {
        fprintf(stderr, "Error walking file inode: %" PRIuINUM "\n",
            a_inum);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    free(s_buf);
    tsk_fs_file_close(file1);
    tsk_fs_file_close(s_file2);
    return 0;
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
        tsk_error_reset();
        return 1;
    }

    if ((fs = tsk_fs_open_img(img, 0, (TSK_FS_TYPE_ENUM) 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    if (testfile(fs, 33)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }

    tsk_fs_close(fs);
    tsk_img_close(img);
    return 0;
}

/* This test checks the SLACK flags and verifies
 * that we read data from the slack space
 */
int
test_fat_slack()
{
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    const char *tname = "fat-img-kw";
    char fname[512];
    TSK_FS_FILE *file1;
    char buf[512];
    ssize_t retval;

    snprintf(fname, 512, "%s/fat-img-kw.dd", s_root);
    if ((img = tsk_img_open_sing((const TSK_TCHAR *)fname, (TSK_IMG_TYPE_ENUM) 0, 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    if ((fs = tsk_fs_open_img(img, 0, (TSK_FS_TYPE_ENUM) 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }


    // file4.dat
    file1 = tsk_fs_file_open_meta(fs, NULL, 10);
    if (file1 == NULL) {
        fprintf(stderr, "Error opening file4.dat (%s)\n", tname);
        return 1;
    }

    // verify expected size
    if (file1->meta->size != 631) {
        fprintf(stderr,
            "Error: file4.dat not expected size (%" PRIuOFF ") (%s)\n",
            file1->meta->size, tname);
        return 1;
    }

    // try to read all of last sector with/out Slack set
    retval =
        tsk_fs_file_read(file1, 512, buf, 512,
        (TSK_FS_FILE_READ_FLAG_ENUM) 0);
    if (retval == -1) {
        fprintf(stderr,
            "Error reading file4.dat to end w/out slack flag\n");
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }
    if (retval != 119) {
        fprintf(stderr,
            "Unexpected return value from reading file4.dat to end w/out slack flag.\n");
        fprintf(stderr, "Expected: 119.  Got: %zd\n", retval);
        return 1;
    }

    retval =
        tsk_fs_file_read(file1, 512, buf, 512,
        TSK_FS_FILE_READ_FLAG_SLACK);
    if (retval == -1) {
        fprintf(stderr, "Error reading file4.dat to end w/slack flag\n");
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }
    if (retval != 512) {
        fprintf(stderr,
            "Unexpected return value from reading file4.dat  w/slack flag.\n");
        fprintf(stderr, "Expected: 512.  Got: %zd\n", retval);
        return 1;
    }

    // verify the term in the slack space
    if (memcmp("3slack3", &buf[385], 7) != 0) {
        fprintf(stderr,
            "slack string not found in file4.dat slack space: %x %x %x %x %x %x %x\n",
            buf[385], buf[386], buf[387], buf[388], buf[389], buf[390],
            buf[391]);
        return 1;
    }


    tsk_fs_close(fs);
    tsk_img_close(img);
    return 0;
}

/* This test checks the RECOVER flags 
 */
int
test_fat_recover()
{
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    const char *tname = "fe_test_1.img-FAT";
    char fname[512];
    TSK_FS_FILE *file1;
    TSK_FS_FILE *file2;
    char buf[512];
    ssize_t retval;

    snprintf(fname, 512, "%s/fe_test_1.img", s_root);
    if ((img = tsk_img_open_sing((const TSK_TCHAR *)fname, (TSK_IMG_TYPE_ENUM) 0, 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    if ((fs =
            tsk_fs_open_img(img, 41126400,
                (TSK_FS_TYPE_ENUM) 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }


    // fragmented.html
    const char *fname2 = "fragmented.html";
    file1 = tsk_fs_file_open_meta(fs, NULL, 1162);
    if (file1 == NULL) {
        fprintf(stderr, "Error opening %s (%s)\n", fname2, tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    // verify expected size
    if (file1->meta->size != 5905) {
        fprintf(stderr,
            "Error: %s not expected size (%" PRIuOFF ") (%s)\n", fname2,
            file1->meta->size, tname);
        return 1;
    }

    // verify we can open it via name as well
    file2 = tsk_fs_file_open(fs, NULL, "/deleted/fragmented.html");
    if (file2 == NULL) {
        fprintf(stderr,
            "Error opening /deleted/fragmented.html via path name (%s)\n",
            tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    if (file2->name == NULL) {
        fprintf(stderr,
            "Opening /deleted/fragmented.html via path name did not have name set(%s)\n",
            tname);
        return 1;
    }

    if (strcmp(file2->name->name, fname2) != 0) {
        fprintf(stderr,
            "Opening /deleted/fragmented.html via path had incorrect name set (%s) (%s)\n",
            file2->name->name, tname);
        return 1;
    }

    if ((file2->name->meta_addr != file2->meta->addr)
        || (file2->meta->addr != file1->meta->addr)) {
        fprintf(stderr,
            "Opening /deleted/fragmented.html via path had incorrect meta addresses (%"
            PRIuINUM " %" PRIuINUM " %" PRIuINUM " (%s)\n",
            file2->name->meta_addr, file2->meta->addr, file1->meta->addr,
            tname);
        return 1;
    }
    tsk_fs_file_close(file2);
    file2 = NULL;

    // try to read past end of first 2048-byte cluster
    retval =
        tsk_fs_file_read(file1, 2048, buf, 512,
        (TSK_FS_FILE_READ_FLAG_ENUM) 0);
    if (retval == -1) {
        fprintf(stderr, "Error reading %s past end w/out Recover flag\n",
            fname2);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }
    // current behavior is to return 0s in "unitialized" space 
    //if (retval != 0) {
    if (retval != 512) {
        fprintf(stderr,
            "Unexpected return value from reading %s past end w/out Recover flag.\n",
            fname2);
        fprintf(stderr, "Expected: 0.  Got: %zd\n", retval);
        return 1;
    }

    retval =
        tsk_fs_file_read(file1, 2048, buf, 512,
        (TSK_FS_FILE_READ_FLAG_ENUM) 0);
    if (retval == -1) {
        fprintf(stderr, "Error reading %s past end w/Recover flag\n",
            fname2);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }
    if (retval != 512) {
        fprintf(stderr,
            "Unexpected return value from %s past end w/Recover flag.\n",
            fname2);
        fprintf(stderr, "Expected: 512.  Got: %zd\n", retval);
        return 1;
    }

    // verify the term in the slack space
    if (memcmp("appear", buf, 6) != 0) {
        fprintf(stderr,
            "expected string not found in %s recovery: %c %c %c %c %c %c\n",
            fname2, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
        return 1;
    }

    tsk_fs_file_close(file1);
    tsk_fs_close(fs);
    tsk_img_close(img);
    return 0;
}

/* This test checks the SLACK flags and verifies
 * that we read data from the slack space
 */
int
test_ntfs_slack_ads()
{
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    const char *tname = "ntfs-img-kw";
    char fname[512];
    TSK_FS_FILE *file1;
    char buf[512];
    ssize_t retval;

    snprintf(fname, 512, "%s/ntfs-img-kw-1.dd", s_root);
    if ((img = tsk_img_open_sing((const TSK_TCHAR *)fname, (TSK_IMG_TYPE_ENUM) 0, 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    if ((fs = tsk_fs_open_img(img, 0, (TSK_FS_TYPE_ENUM) 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }


    // file-n-44.dat
    file1 = tsk_fs_file_open_meta(fs, NULL, 36);
    if (file1 == NULL) {
        fprintf(stderr, "Error opening file-n-4.dat (%s)\n", tname);
        return 1;
    }

    // verify expected size
    if (file1->meta->size != 2000) {
        fprintf(stderr,
            "Error: file-n-4.dat not expected size (%" PRIuOFF ") (%s)\n",
            file1->meta->size, tname);
        return 1;
    }

    // try to read all of last sector with/out Slack set
    retval =
        tsk_fs_file_read(file1, 1536, buf, 512,
        (TSK_FS_FILE_READ_FLAG_ENUM) 0);
    if (retval == -1) {
        fprintf(stderr,
            "Error reading file-n-4.dat to end w/out slack flag (%s)\n",
            tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }
    if (retval != 464) {
        fprintf(stderr,
            "Unexpected return value from reading file-n-4.dat to end w/out slack flag (%s).\n",
            tname);
        fprintf(stderr, "Expected: 464.  Got: %zd\n", retval);
        return 1;
    }

    retval =
        tsk_fs_file_read(file1, 1536, buf, 512,
        TSK_FS_FILE_READ_FLAG_SLACK);
    if (retval == -1) {
        fprintf(stderr,
            "Error reading file-n-4.dat to end w/slack flag (%s)\n",
            tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }
    if (retval != 512) {
        fprintf(stderr,
            "Unexpected return value from reading file-n-4.dat  w/slack flag. (%s)\n",
            tname);
        fprintf(stderr, "Expected: 512.  Got: %zd\n", retval);
        return 1;
    }

    // verify the term in the slack space
    if (memcmp("n-slack", &buf[485], 7) != 0) {
        fprintf(stderr,
            "slack string not found in file-n-4.dat slack space: %c %c %c %c %c %c %c (%s)\n",
            buf[485], buf[486], buf[487], buf[488], buf[489], buf[490],
            buf[491], tname);
        return 1;
    }


    // try to read past end of file 
    retval =
        tsk_fs_file_read(file1, 2001, buf, 32,
        (TSK_FS_FILE_READ_FLAG_ENUM) 0);
    if (retval != -1) {
        fprintf(stderr,
            "Unexpected return value from reading file-n-4.dat after end of file (%s).\n",
            tname);
        fprintf(stderr, "Expected: -1.  Got: %zd\n", retval);
        return 1;
    }


    tsk_fs_file_close(file1);

    // file-n-5.dat
    file1 = tsk_fs_file_open_meta(fs, NULL, 37);
    if (file1 == NULL) {
        fprintf(stderr, "Error opening file-n-5.dat (%s)\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    // check the default size to make sure it is the default $Data
    if (file1->meta->size != 1300) {
        fprintf(stderr,
            "file-n-5.dat size is not 1300 (%" PRIuOFF ") (%s)",
            file1->meta->size, tname);
        return 1;
    }

    // test the getsize API for both attributes
    const TSK_FS_ATTR *fs_attr =
        tsk_fs_file_attr_get_type(file1, TSK_FS_ATTR_TYPE_NTFS_DATA, 3, 1);
    if (!fs_attr) {
        fprintf(stderr,
            "Error getting data attribute 3 in file-n-5.dat (%s)", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }
    if (fs_attr->size != 1300) {
        fprintf(stderr,
            "file-n-5.dat size (via getsize) is not 1300 (%" PRIuOFF
            ") (%s)", fs_attr->size, tname);
        return 1;
    }

    fs_attr =
        tsk_fs_file_attr_get_type(file1, TSK_FS_ATTR_TYPE_NTFS_DATA, 5, 1);
    if (!fs_attr) {
        fprintf(stderr,
            "Error getting size of attribute 5 in file-n-5.dat (%s)",
            tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }
    if (fs_attr->size != 2000) {
        fprintf(stderr,
            "file-n-5.dat:here size (via getsize) is not 2000 (%" PRIuOFF
            ") (%s)", fs_attr->size, tname);
        return 1;
    }

    tsk_fs_file_close(file1);

    tsk_fs_close(fs);
    tsk_img_close(img);
    return 0;
}

int
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
        tsk_error_reset();
        return 1;
    }

    if ((fs = tsk_fs_open_img(img, 32256, (TSK_FS_TYPE_ENUM) 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    if (testfile(fs, 31)) {
        fprintf(stderr, "%s error (non-resident)\n", tname);
        return 1;
    }

    if (testfile(fs, 32)) {
        fprintf(stderr, "%s error (resident)\n", tname);
        return 1;
    }

    tsk_fs_close(fs);
    tsk_img_close(img);
    return 0;
}

int
test_ntfs_comp()
{
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    const char *tname = "ntfs-comp-1";
    char fname[512];

    snprintf(fname, 512, "%s/ntfs-comp-1.img", s_root);
    if ((img = tsk_img_open_sing((const TSK_TCHAR *)fname, (TSK_IMG_TYPE_ENUM) 0, 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    if ((fs = tsk_fs_open_img(img, 0, (TSK_FS_TYPE_ENUM) 0)) == NULL) {
        fprintf(stderr, "Error opening %s image\n", tname);
        tsk_error_print(stderr);
        tsk_error_reset();
        return 1;
    }

    if (testfile(fs, 34)) {
        fprintf(stderr, "%s error (both)\n", tname);
        return 1;
    }

    if (testfile(fs, 32)) {
        fprintf(stderr, "%s error (sparse)\n", tname);
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
        fprintf(stderr, "missing test image root directory\n");
        return 1;
    }
    s_root = argv[1];

    if (test_fat12())
        return 1;
    if (test_fat_slack())
        return 1;
    if (test_fat_recover())
        return 1;
    if (test_ntfs_fe())
        return 1;
    if (test_ntfs_comp())
        return 1;
    if (test_ntfs_slack_ads())
        return 1;

    printf("Tests Passed\n");
    return 0;
}
