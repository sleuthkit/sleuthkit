/* 
*
* This is a sample file that shows how to use some of the basic C++
* POSIX-style library functions in The Sleuth Kit (www.sleuthkit.org).
* There are also callback-style functions that can be used to read
* the data and partitions.
*
* Copyright (c) 2008>, Brian Carrier <carrier <at> sleuthkit <dot> org>
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 
* - Redistributions of source code must retain the above copyright notice,
*   this list of conditions and the following disclaimer.
* - Redistributions in binary form must reproduce the above copyright
*   notice, this list of conditions and the following disclaimer in the
*   documentation and/or other materials provided with the distribution.
* - Neither the Sleuth Kit name nor the names of its contributors may be
*   used to endorse or promote products derived from this software without
*   specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <tsk/libtsk.h>

static TskHdbInfo *hdb_info;

#define DO_HASHING  1
#define DO_HASHLOOKUP 0


/** 
 * dent_walk callback function 
 */
static TSK_WALK_RET_ENUM
fileAct(TskFsFile * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    TSK_MD5_CTX *md = (TSK_MD5_CTX *) ptr;
    if (md == NULL)
        return TSK_WALK_CONT;

    TSK_MD5_Update(md, (unsigned char *) buf, (unsigned int) size);

    return TSK_WALK_CONT;
}


/**
 * Process the contents of a file.
 *
 * @return 1 on error and 0 on success 
 */
static uint8_t
procFile(TskFsFile * fs_file, const char *path)
{
    TSK_MD5_CTX md;

    if ((fs_file->getMeta() == NULL) || (fs_file->getName() == NULL))
        return 1;

    if (fs_file->getMeta()->getType() != TSK_FS_META_TYPE_REG)
        return 0;

    //printf("Processing %s%s\n", path, fs_file->name->name);

    int myflags = TSK_FS_FILE_WALK_FLAG_NOID;

    TSK_MD5_Init(&md);

    /* Note that we could also cycle through all of the attributes in the
     * file by using one of the tsk_fs_attr_get() functions and walking it
     * with tsk_fs_attr_walk(). See the File Systems section of the Library
     * User's Guide for more details: 
     * http://www.sleuthkit.org/sleuthkit/docs/api-docs/ */
    if (fs_file->walk
        ((TSK_FS_FILE_WALK_FLAG_ENUM) myflags, fileAct,
            (void *) &md)) {
        // ignore errors from deleted files that were being recovered
        if (tsk_error_get_errno() != TSK_ERR_FS_RECOVER) {
            printf("Processing: %s/%s (%" PRIuINUM ")\n", path,
                fs_file->getName()->getName(), fs_file->getMeta()->getAddr());
            tsk_error_print(stderr);
        }
        tsk_error_reset();
    }
    // otherwise, compute the hash of the file.
    else {
        unsigned char hash[16];

        TSK_MD5_Final(hash, &md);
#if 0
        {
            int i;
            printf("Hash of %s/%s: ", path, fs_file->name->name);

            for (i = 0; i < 16; i++) {
                printf("%x%x", (hash[i] >> 4) & 0xf, hash[i] & 0xf);
            }
            printf("\n");
        }
#endif
#if DO_HASHLOOKUP
        {
            int retval;
            retval = tsk_hdb_lookup_raw(hdb_info, (uint8_t *) hash, 16,
                TSK_HDB_FLAG_QUICK, NULL, NULL);
            if (retval == 1) {
                //printf("Ignoring file %s\n", fs_dent->name);
            }
            else if (retval == 0) {
//            printf("Not Ignoring: %s/%s\n", path, name);
            }
        }
#endif
    }

    return 0;
}

/**
 * file name walk callback.  Walk the contents of each file 
 * that is found.
 */
static TSK_WALK_RET_ENUM
dirAct(TskFsFile * fs_file, const char *path, void *ptr)
{
	fprintf(stdout,
               "file systems file name: %s\n", fs_file->getName()->getName());

    /* Ignore NTFS System files */
    if ((TSK_FS_TYPE_ISNTFS(fs_file->getFsInfo()->getFsType()))
        && (fs_file->getName()->getName()[0] == '$'))
        return TSK_WALK_CONT;

    /* If the name has corresponding metadata, then walk it */
    if (fs_file->getMeta()) {
        procFile(fs_file, path);
    }

    return TSK_WALK_CONT;
}




/** 
 * Analyze the volume starting at byte offset 'start' 
 * and walk each file that can be found.
 *
 * @param img Disk image to be analyzed.
 * @param start Byte offset of volume starting location.
 *
 * @return 1 on error and 0 on success
*/
static uint8_t
procFs(TskImgInfo * img_info, TSK_OFF_T start)
{
    TskFsInfo *fs_info = new TskFsInfo();

    /* Try it as a file system */
    if (fs_info->open(img_info, start, TSK_FS_TYPE_DETECT))
    {
        delete fs_info;
        tsk_error_print(stderr);

        /* We could do some carving on the volume data at this point */

        return 1;
    }

    /* Walk the files, starting at the root directory */
    if (fs_info->dirWalk(fs_info->getRootINum(),
            (TSK_FS_DIR_WALK_FLAG_ENUM) (TSK_FS_DIR_WALK_FLAG_RECURSE),
            dirAct, NULL)) {
        delete fs_info;
        tsk_error_print(stderr);
        fs_info->close();
        return 1;
    }

    /* We could do some analysis of unallocated blocks at this point...  */

    fs_info->close();
    delete fs_info;
    return 0;
}

/**
 * Volume system walk callback function that will analyze 
 * each volume to find a file system.
 */
static TSK_WALK_RET_ENUM
vsAct(TskVsInfo * vs_info, const TskVsPartInfo * vs_part, void *ptr)
{
    if (procFs(const_cast<TskImgInfo *>(vs_info->getImgInfo()), const_cast<TskVsPartInfo *>(vs_part)->getStart() * vs_info->getBlockSize())) {
        // if we return ERROR here, then the walk will stop.  But, the 
        // error could just be because we looked into an unallocated volume.
        // do any special error handling / reporting here.
        tsk_error_reset();
        return TSK_WALK_CONT;
    }

    return TSK_WALK_CONT;
}


/**
 * Process the data as a volume system to find the partitions
 * and volumes.  
 * File system analysis will be performed on each partition.
 *
 * @param img Image file information structure for data to analyze
 * @param start Byte offset to start analyzing from. 
 *
 * @return 1 on error and 0 on success
 */
static uint8_t
procVs(TskImgInfo * img_info, TSK_OFF_T start)
{
    TskVsInfo *vs_info = new TskVsInfo();;

    // USE mm_walk to get the volumes 
    if (vs_info->open(img_info, start, TSK_VS_TYPE_DETECT)) {
        if (tsk_verbose)
            fprintf(stderr,
                "Error determining volume system -- trying file systems\n");

        /* There was no volume system, but there could be a file system */
        tsk_error_reset();
        if (procFs(img_info, start)) {
            delete vs_info;
            return 1;
        }
    }
    else {
        fprintf(stderr, "Volume system open, examining each\n");

        /* Walk the allocated volumes (skip metadata and unallocated volumes) */
        if (vs_info->vsPartWalk(0, vs_info->getPartCount() - 1,
                (TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC), vsAct,
                NULL)) {
            delete vs_info;
            return 1;
        }
    }
    delete vs_info;
    return 0;
}


int
main(int argc, char **argv1)
{
    TskImgInfo *img_info = new TskImgInfo();
    TSK_TCHAR **argv;

#ifdef TSK_WIN32
    // On Windows, get the wide arguments (mingw doesn't support wmain)
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        delete img_info;
        fprintf(stderr, "Error getting wide arguments\n");
        exit(1);
    }
#else
    argv = (TSK_TCHAR **) argv1;
#endif

    if (argc != 2) {
        delete img_info;
        fprintf(stderr, "Missing image name\n");
        exit(1);
    }

#if DO_HASHLOOKUP
    /* Setup hash infrastructure */
    if ((hdb_info =
            tsk_hdb_open(_TSK_T("/XXX/NSRLFile.txt"),
                TSK_HDB_OPEN_NONE)) == NULL) {
        delete img_info;
        tsk_error_print(stderr);
        exit(1);
    }

    if (tsk_hdb_hasindex(hdb_info, TSK_HDB_HTYPE_MD5_ID) == 0) {
        delete img_info;
        fprintf(stderr,
            "Hash database does not have an index (create one using hfind -i nsrl-md5 HASHFILE\n");
        exit(1);
    }
#else
    hdb_info = NULL;
#endif

    if (img_info->open(argv[1], TSK_IMG_TYPE_DETECT, 0) == 1) {
        delete img_info;
        fprintf(stderr, "Error opening file\n");
        tsk_error_print(stderr);
        exit(1);
    }

    if (procVs(img_info, 0)) {
        delete img_info;
        tsk_error_print(stderr);
        exit(1);
    }

    delete img_info;
    return 0;
}
