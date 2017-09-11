/*
* The Sleuth Kit 
*
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2008-2011 Brian Carrier.  All Rights reserved
*
*
* This software is distributed under the Common Public License 1.0
*
*/

/* Test and compare the directory entry read apis */

/* TESTS: 
 * Need to uncommen parent addr check in open() check when fs_meta is defined
 */

#include "tsk/tsk_tools_i.h"

static char *s_root;


/* Compare two dents and return 1 if they are diff.
 * print error message if a_print is non-zero.
 */
static int
compare_names(const TSK_FS_NAME * fs_name1, const TSK_FS_NAME * fs_name2,
    uint8_t a_print)
{
    if (fs_name1->type != fs_name2->type) {
        if (a_print) {
            fprintf(stderr, "ent type mismatch: %x %x\n",
                fs_name1->type, fs_name2->type);
        }
        return 1;
    }
    if (fs_name1->flags != fs_name2->flags) {
        if (a_print) {
            fprintf(stderr, "flags mismatch: %x %x\n",
                fs_name1->flags, fs_name2->flags);
        }
        return 1;
    }
    if (fs_name1->meta_addr != fs_name2->meta_addr) {
        if (a_print) {
            fprintf(stderr,
                "inode address mismatch: %" PRIuINUM " %" PRIuINUM "\n",
                fs_name1->meta_addr, fs_name2->meta_addr);
        }
        return 1;
    }

    if (fs_name1->name == NULL) {
        if (fs_name2->name) {
            if (a_print)
                fprintf(stderr, "dent1 name is NULL, dent2 is not\n");
            return 1;
        }
    }
    else if (fs_name2->name == NULL) {
        if (a_print)
            fprintf(stderr, "dent2 name is NULL, dent1 is not\n");
        return 1;
    }
    else if (strcmp(fs_name1->name, fs_name2->name)) {
        if (a_print)
            fprintf(stderr, "name mismatch: %s %s\n",
                fs_name1->name, fs_name2->name);
        return 1;
    }

    return 0;
}


/* file walk callback that counts how many entries there are in a
 * directory */
static TSK_WALK_RET_ENUM
dir_walk_count_cb(TSK_FS_FILE * a_fs_file, const char *a_path, void *a_ptr)
{
    size_t *a = (size_t *) a_ptr;
    *a = *a + 1;
    return TSK_WALK_CONT;
}


/* file walk callback that looks for an fs_name given as the arg pointer. */
static int s_found;
static TSK_WALK_RET_ENUM
dir_walk_comp_cb(TSK_FS_FILE * a_fs_file, const char *a_path, void *a_ptr)
{
    const TSK_FS_FILE *fs_file2 = (const TSK_FS_FILE *) a_ptr;

    if (compare_names(a_fs_file->name, fs_file2->name, 0) == 0) {
        s_found = 1;
        return TSK_WALK_STOP;
    }

    return TSK_WALK_CONT;
}


/* Test function that compares the dir_open/dir_get() APIs
 * with the dir_walk results
 * @param a_addr Address of directory to analyze
 * @returns 1 if a test failed.
 */
static int
test_walk_apis(TSK_FS_INFO * a_fs, TSK_INUM_T a_addr)
{
    TSK_FS_DIR *fs_dir;
    int retval = 0;

    fs_dir = tsk_fs_dir_open_meta(a_fs, a_addr);
    if (!fs_dir) {
        fprintf(stderr, "Error opening dir %" PRIuINUM " via meta\n",
            a_addr);
        tsk_error_print(stderr);
        return 1;
    }

    // verify they have the same number of entries
    // walk the directory to get its count
    size_t walk_size = 0;
    if (tsk_fs_dir_walk(a_fs, a_addr, (TSK_FS_DIR_WALK_FLAG_ENUM) 0,
            dir_walk_count_cb, &walk_size)) {
        fprintf(stderr, "Error doing dent walk on dir %" PRIuINUM "\n",
            a_addr);
        retval = 1;
        goto walk_cleanup;
    }

    if (walk_size != tsk_fs_dir_getsize(fs_dir)) {
        fprintf(stderr,
            "Size returned by dir_walk different from dir_getsize: %"
            PRIuINUM ": %" PRIuSIZE " %" PRIuSIZE "\n", a_addr, walk_size,
            tsk_fs_dir_getsize(fs_dir));
        retval = 1;
        goto walk_cleanup;
    }

    // verify each entry is the same
    for (size_t i = 0; i < tsk_fs_dir_getsize(fs_dir); i++) {
        TSK_FS_FILE *fs_file;

        fs_file = tsk_fs_dir_get(fs_dir, i);
        if (fs_file == NULL) {
            fprintf(stderr,
                "Error getting entry %" PRIuSIZE " from directory %"
                PRIuINUM "\n", i, a_addr);
            tsk_error_print(stderr);
            retval = 1;
            goto walk_cleanup;
        }
        if (fs_file->meta == NULL) {
            fprintf(stderr,
                "Error: %s (%" PRIuINUM
                ") does not have meta set in dir: \n", fs_file->name->name,
                fs_file->name->meta_addr);
            retval = 1;
            goto walk_cleanup;
        }

        s_found = 0;
        if (tsk_fs_dir_walk(a_fs, a_addr, (TSK_FS_DIR_WALK_FLAG_ENUM) 0,
                dir_walk_comp_cb, (void *) fs_file)) {
            fprintf(stderr, "Error doing dent walk on dir %" PRIuINUM "\n",
                a_addr);
            retval = 1;
            goto walk_cleanup;
        }
        if (s_found == 0) {
            fprintf(stderr,
                "entry %" PRIuSIZE " in dir not found via walk: %s\n", i,
                fs_file->name->name);
            retval = 1;
            goto walk_cleanup;
        }
        tsk_fs_file_close(fs_file);
    }

  walk_cleanup:
    tsk_fs_dir_close(fs_dir);
    return retval;
}

/* Compare the differences between dir_open_meta and dir_open 
 * @param a_path Path of directory to open
 * @param a_addr The metadata address of the same directory as the path
 * @returns 1 if a test failed
 */
static int
test_dir_open_apis(TSK_FS_INFO * a_fs, const char *a_path,
    TSK_INUM_T a_addr)
{
    TSK_FS_DIR *fs_dir_m;
    TSK_FS_DIR *fs_dir_p;
    TSK_FS_DIR *fs_dir_tmp;
    TSK_FS_FILE *fs_file_m;
    TSK_FS_FILE *fs_file_p;
    int retval = 0;
    size_t entry = 0;

    // open via inode addr
    fs_dir_m = tsk_fs_dir_open_meta(a_fs, a_addr);
    if (!fs_dir_m) {
        fprintf(stderr, "Error opening dir %" PRIuINUM " via meta\n",
            a_addr);
        tsk_error_print(stderr);
        return 1;
    }

    /* open the root directory to throw some more state into the system
     * in case data is cached from first call */
    fs_dir_tmp = tsk_fs_dir_open_meta(a_fs, a_fs->root_inum);
    if (!fs_dir_tmp) {
        fprintf(stderr, "Error opening root directory via meta\n");
        tsk_error_print(stderr);
        return 1;
    }

    // open via path
    fs_dir_p = tsk_fs_dir_open(a_fs, a_path);
    if (!fs_dir_p) {
        fprintf(stderr, "Error opening directory %s\n", a_path);
        tsk_error_print(stderr);
        return 1;
    }

    // test that path has the name structure set (correctly)
    if ((fs_dir_p->fs_file == NULL) || (fs_dir_p->fs_file->name == NULL)) {
        fprintf(stderr, "dir opened via path has null name (%s)\n",
            a_path);
        retval = 1;
        goto open_cleanup;
    }

    if (fs_dir_p->fs_file->name->meta_addr !=
        fs_dir_p->fs_file->meta->addr) {
        fprintf(stderr,
            "dir opened via path has different meta addresses in name and meta (%s) (%"
            PRIuINUM " vs %" PRIuINUM "\n", a_path,
            fs_dir_p->fs_file->name->meta_addr,
            fs_dir_p->fs_file->meta->addr);
        retval = 1;
        goto open_cleanup;
    }

    // verify both methods have same dir addr
    if (fs_dir_p->fs_file->meta->addr != fs_dir_m->fs_file->meta->addr) {
        fprintf(stderr,
            "parent dir addrs from fs_dir_open_meta and via path are different: %"
            PRIuINUM " vs %" PRIuINUM " (%s - %" PRIuINUM "\n",
            fs_dir_p->fs_file->meta->addr, fs_dir_m->fs_file->meta->addr,
            a_path, a_addr);
        retval = 1;
        goto open_cleanup;
    }

    // verify path method has same dir addr as open via meta
    if (fs_dir_p->fs_file->meta->addr != a_addr) {
        fprintf(stderr,
            "parent dir addrs from fs_dir_open is diff from meta address %"
            PRIuINUM " (%s - %" PRIuINUM "\n",
            fs_dir_p->fs_file->meta->addr, a_path, a_addr);
        retval = 1;
        goto open_cleanup;
    }

    // verify both have same size
    if (tsk_fs_dir_getsize(fs_dir_p) != tsk_fs_dir_getsize(fs_dir_m)) {
        fprintf(stderr,
            "sizes from fs_dir_open_meta and via path are different: %"
            PRIuSIZE " vs %" PRIuSIZE " (%s - %" PRIuINUM "\n",
            tsk_fs_dir_getsize(fs_dir_p), tsk_fs_dir_getsize(fs_dir_m),
            a_path, a_addr);
        retval = 1;
        goto open_cleanup;
    }


    // compare the first entry in both. 
    if (tsk_fs_dir_getsize(fs_dir_p) == 0) {
        fprintf(stderr, "directory sizes are 0\n");
        retval = 1;
        goto open_cleanup;
    }

    fs_file_m = tsk_fs_dir_get(fs_dir_m, 0);
    if (fs_file_m == NULL) {
        fprintf(stderr,
            "Error opening entry 0 from meta open: %" PRIuINUM "\n",
            a_addr);
        tsk_error_print(stderr);
        retval = 1;
        goto open_cleanup;
    }

    fs_file_p = tsk_fs_dir_get(fs_dir_p, 0);
    if (fs_file_p == NULL) {
        fprintf(stderr,
            "Error opening entry 0 from path open: %" PRIuINUM "\n",
            a_addr);
        tsk_error_print(stderr);
        retval = 1;
        goto open_cleanup;
    }

    if (compare_names(fs_file_p->name, fs_file_m->name, 1)) {
        fprintf(stderr, "results from entry 0 are different\n");
        retval = 1;
        goto open_cleanup;
    }
    tsk_fs_file_close(fs_file_m);
    tsk_fs_file_close(fs_file_p);


    // compare the last entry in both
    entry = tsk_fs_dir_getsize(fs_dir_m) - 1;
    fs_file_m = tsk_fs_dir_get(fs_dir_m, entry);
    if (fs_file_m == NULL) {
        fprintf(stderr,
            "Error opening entry %" PRIuSIZE " from meta open: %" PRIuINUM
            "\n", entry, a_addr);
        tsk_error_print(stderr);
        retval = 1;
        goto open_cleanup;
    }

    fs_file_p = tsk_fs_dir_get(fs_dir_p, entry);
    if (fs_file_p == NULL) {
        fprintf(stderr,
            "Error opening entry %" PRIuSIZE " from path open: %" PRIuINUM
            "\n", entry, a_addr);
        tsk_error_print(stderr);
        retval = 1;
        goto open_cleanup;
    }

    if (compare_names(fs_file_p->name, fs_file_m->name, 1)) {
        fprintf(stderr, "results from entry %" PRIuSIZE " are different\n",
            entry);
        retval = 1;
        goto open_cleanup;
    }
    tsk_fs_file_close(fs_file_m);
    tsk_fs_file_close(fs_file_p);


  open_cleanup:
    tsk_fs_dir_close(fs_dir_p);
    tsk_fs_dir_close(fs_dir_tmp);
    tsk_fs_dir_close(fs_dir_m);

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

    if (test_dir_open_apis(fs, "/", 2)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }


    if (test_walk_apis(fs, 2)) {
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

    if (test_dir_open_apis(fs, "/allocated", 30)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }

    if (test_walk_apis(fs, 30)) {
        fprintf(stderr, "%s failure\n", tname);
        return 1;
    }

    tsk_fs_close(fs);
    tsk_img_close(img);
    return 0;
}

#if 0
int
test_ntfs_comp()
{
    TSK_FS_INFO *fs;
    TSK_IMG_INFO *img;
    char *tname = "ntfs-comp-1";
    char fname[512];

    snprintf(fname, 512, "%s/ntfs-comp-1.img", s_root);
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
#endif


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
