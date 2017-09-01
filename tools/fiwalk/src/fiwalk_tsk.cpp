/*
 * SleuthKit support code for fiwalk
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
#include "fiwalk.h"
#include "arff.h"
#include "plugin.h"
#include "unicode_escape.h"
#include "tsk/fs/tsk_fatfs.h"

#define MAX_SPARSE_SIZE 1024*1024*64

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifdef HAVE_ERR_H
#include "err.h"
#endif


/****************************************************************
 ** Support Code.
 ****************************************************************/

/* FS_INFO defined in ~/sleuthkit-2.05/src/fstools/fs_tools.h
 * IMG_INFO defined in img_tools.h
 * img_open - opens the image; calls do_dimage
 * do_dimage - analyizes the image
 *        mm_open - opens the volume; mm_part_walk - walk each volume;
 *                  calls mm_act for each
 * mm_act - analyizes each partition; calls do_vol for ones that we can analyze
 * do_vol - analyizes each volume
 *       fs_open - opens the file system; dent_walk
 *               - walks the directory structure.
 *               - calls dent_act for each file
 * dent_act - prints file name; calls file_walk() to read each file;
 *          - calls file_act for each sector
 * file_act - prints the block number
 */

/**
 * file_act:
 *  -- obtain the address of each data unit
 *  -- optionally calculate the mac or save the data
 *
 */
TSK_WALK_RET_ENUM
file_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr, char *buf,
	 size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    content *ci = (content *)ptr;
    return ci->file_act(fs_file,a_off,addr,buf,size,flags);
}

/* This is modeled on print_dent_act printit in ./tsk/fs/fls_lib.c
 * See also tsk_fs_name_print() in ./tsk/fs/fs_name.c
 */

static uint8_t
process_tsk_file(TSK_FS_FILE * fs_file, const char *path)
{
    /* Use a flag to determine if a file is generically fit for plugins. */
    bool can_run_plugin;

    /* Make sure that the SleuthKit structures are properly set */
    if (fs_file->name == NULL) 
        return 1;
    if (fs_file->meta == NULL && opt_debug)
        printf("File: %s %s  has no meta\n", path, fs_file->name->name);

    /* SleuthKit meta types are defined in tsk_fs.h.*/

    if (opt_debug) printf("Processing %s%s type=%s (0x%x) \n",
			  path, fs_file->name->name,
			  tsk_fs_name_type_str[fs_file->name->type],fs_file->name->type);

    /* Recover the filename from the fs_dent, if it is provided */
    content ci(fs_file->fs_info->img_info);	// where the content will go
    ci.evidence_dirname = path;
    ci.set_filename(fs_file->name->name);

    /* If we are filtering and we have a filename, see if we want this file. */
    if (ci.name_filtered()) return 0;

    /* Looks like we are processing */
    if(a) a->new_row();			// tell ARFF we are starting a new row
    if(x) x->push("fileobject"); 	// tell XML we are starting a new XML object
    if(opt_parent_tracking)
    {
        if(fs_file->name->par_addr){
            if(x)
            {
                x->push("parent_object");
                file_info("inode", fs_file->name->par_addr);
                if(x) x->pop();
            }
            if((t||a) && !opt_body_file)
            {
                file_info("parent_inode", fs_file->name->par_addr);
            }
        }
    }

    if(fs_file->meta != NULL)
    {
        /* Get the content if needed */
        if(ci.need_file_walk() && (opt_maxgig==0 || fs_file->meta->size/1000000000 < opt_maxgig)){
    	int myflags = TSK_FS_FILE_WALK_FLAG_NOID;
    	if (opt_no_data) myflags |= TSK_FS_FILE_WALK_FLAG_AONLY;
    	if (tsk_fs_file_walk (fs_file, (TSK_FS_FILE_WALK_FLAG_ENUM) myflags, file_act, (void *) &ci)) {
    
    	    // ignore errors from deleted files that were being recovered
    	    //if (tsk_errno != TSK_ERR_FS_RECOVER) {
    	    if (tsk_error_get_errno() != TSK_ERR_FS_RECOVER) {
    		if(opt_debug){
    		    fprintf(stderr,"Processing: %s/%s (%" PRIuINUM ")\n", path,
    			   fs_file->name->name, fs_file->meta->addr);
    		    tsk_error_print(stderr);
    		}
    	    }
    	    tsk_error_reset();
    	}
        }
    }

    if(file_count_max && file_count>file_count_max) return TSK_WALK_STOP;
    file_count++;

    /* Send through to the plugin if we were doing that.
     * Currently results only go to ARFF file, not to the XML file.
     */

    /* Finally output the informaton */
    if(opt_body_file && (fs_file->meta != NULL)){
	char ls[64];
	tsk_fs_meta_make_ls(fs_file->meta,ls,sizeof(ls));
	fprintf(t,"%s|%s|%" PRId64 "|%s|%d|%d|%" PRId64 "|%d|%d|%d|%d\n",
		ci.h_md5.final().hexdigest().c_str(),ci.filename().c_str(),fs_file->meta->addr,
		ls,fs_file->meta->uid,fs_file->meta->gid,
		fs_file->meta->size,
		(uint32_t)(fs_file->meta->atime),
		(uint32_t)fs_file->meta->mtime,
		(uint32_t)fs_file->meta->ctime,
		(uint32_t)fs_file->meta->crtime);
	return TSK_WALK_CONT;
    }

    /* Available information in fs_file:
     * int fs_file->tag (internal)
     * TSK_FS_NAME *fs_file->name (file name)
     * TSK_FS_META *fs_file->meta
     * TSK_FS_INFO *fs_file->fs_info
     */

    /* fs_file->name */

    if(ci.has_filename()) file_info("filename",validateOrEscapeUTF8(ci.filename()));
    file_info("partition",current_partition_num);
    file_info("id",next_id++);
    file_info("name_type",tsk_fs_name_type_str[fs_file->name->type]);

    if(fs_file->meta != NULL)
    {
        /* fs_file->meta */
        file_info("filesize",fs_file->meta->size);
        if(fs_file->meta->flags & TSK_FS_META_FLAG_ALLOC)   file_info("alloc",1);
        if(fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC) file_info("unalloc",1);
        if(fs_file->meta->flags & TSK_FS_META_FLAG_USED)    file_info("used",1);
        if(fs_file->meta->flags & TSK_FS_META_FLAG_UNUSED)  file_info("unused",1);
        if(fs_file->meta->flags & TSK_FS_META_FLAG_ORPHAN)  file_info("orphan",1);
        if(fs_file->meta->flags & TSK_FS_META_FLAG_COMP)    file_info("compressed",1);
    
        file_info("inode",fs_file->meta->addr);
        file_info("meta_type",fs_file->meta->type);
        file_info("mode",fs_file->meta->mode); // *** REPLACE WITH drwx-rw-rw or whatever
        file_info("nlink",fs_file->meta->nlink);
        file_info("uid",fs_file->meta->uid);
        file_info("gid",fs_file->meta->gid);
    
    	/* Special processing for FAT */
    	if(TSK_FS_TYPE_ISFAT(fs_file->fs_info->ftype))
    	{
           if(fs_file->meta->mtime) file_infot("mtime",fs_file->meta->mtime, fs_file->fs_info->ftype);
           if(fs_file->meta->ctime) file_infot("ctime",fs_file->meta->ctime, fs_file->fs_info->ftype);
           if(fs_file->meta->atime) file_infot("atime",fs_file->meta->atime, fs_file->fs_info->ftype);
           if(fs_file->meta->crtime) file_infot("crtime",fs_file->meta->crtime, fs_file->fs_info->ftype);
        }
    	else{
           if(fs_file->meta->mtime) file_infot("mtime",fs_file->meta->mtime);
           if(fs_file->meta->ctime) file_infot("ctime",fs_file->meta->ctime);
           if(fs_file->meta->atime) file_infot("atime",fs_file->meta->atime);
           if(fs_file->meta->crtime) file_infot("crtime",fs_file->meta->crtime);
    	}
    
        /* TK: do content_ptr */
        if(fs_file->meta->seq!=0) file_info("seq",fs_file->meta->seq);
    
        /* Special processing for EXT */
        if(TSK_FS_TYPE_ISEXT(fs_file->fs_info->ftype)){
    	if(fs_file->meta->time2.ext2.dtime){
    	    file_infot("dtime",fs_file->meta->time2.ext2.dtime);
    	}
        }
    
        /* Special processing for HFS */
        if(TSK_FS_TYPE_ISHFS(fs_file->fs_info->ftype)){
    	if(fs_file->meta->time2.hfs.bkup_time){
    	    file_infot("bkup_time",fs_file->meta->time2.hfs.bkup_time);
    	}
        }
    }
    // fs_file->meta == NULL)
    else {
        if(fs_file->name->flags & TSK_FS_NAME_FLAG_ALLOC)   file_info("alloc",1);
        if(fs_file->name->flags & TSK_FS_NAME_FLAG_UNALLOC) file_info("unalloc",1);
    
        // @@@ BC: This is a bit confusing.  It seems to be cramming NAME-level info 
        // into places that typically has META-level info. 
        if (fs_file->name->meta_addr!=0)file_info("inode",fs_file->name->meta_addr);
        file_info("meta_type",fs_file->name->type);
        
        if(fs_file->name->meta_seq!=0) file_info("seq",fs_file->name->meta_seq);
    }

    /* Special processing for NTFS */
    if ((TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype))){
	/* Should we cycle through the attributes the way print_dent_act() does? */

	//comment("NTFS and attr=%p",fs_file->meta->attr);

	//char buf[256];
	//snprintf(buf,sizeof(buf),"%"PRIuINUM"-%"PRIu32"-%"PRIu16"",fs_file->meta->addr,fs_file->meta->type,fs_file->meta->id);
	//file_info("sleuthkit_ntfs_id",buf);
    }

    /* TK: do attr_state */
    /* TK: do name2 */
    if(fs_file->meta != NULL)
    {
        if(fs_file->meta->link && fs_file->meta->link[0]!=0){
    	file_info("link_target",fs_file->meta->link);
        }
    }
    ci.write_record();


    /* Processing for regular files and some virtual files: */
    can_run_plugin = false;
    if(fs_file->name->type == TSK_FS_NAME_TYPE_REG){
        can_run_plugin = true;
    }
    else if(fs_file->name->type == TSK_FS_NAME_TYPE_VIRT){
        /* Pass some virtual files to plugins, e.g. $MBR for boot sector virus scans. */
        if(fs_file->name->name){
            if(strcmp(fs_file->name->name, "$MBR") == 0) {
                can_run_plugin = true;
            }
        }
    }

    if(can_run_plugin && ci.do_plugin && ci.total_bytes>0) plugin_process(ci.tempfile_path);

    /* END of file processing */
    if(x) x->pop();
    if(t) fputs("\n",t);
    return TSK_WALK_CONT;
}


/**
 * The callback for each file in the file system.
 * file name walk callback.  Walk the contents of each file
 * that is found.
 */
static TSK_WALK_RET_ENUM
dir_act(TSK_FS_FILE * fs_file, const char *path, void *ptr)
{
    /* Ignore NTFS System files */
    if (opt_ignore_ntfs_system_files
	&& (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype) || TSK_FS_TYPE_ISFAT(fs_file->fs_info->ftype))
        && (fs_file->name->name[0] == '$'))
        return TSK_WALK_CONT;

    /* If the name has corresponding metadata, then walk it */
   	process_tsk_file(fs_file, path);

    return TSK_WALK_CONT;
}


/** proc_fs
 * process each file system that is found in the disk image.
 * @param img_info - pointer to the disk image.
 * @param start - start of the file system.
 * @return 0 if success, -1 if fail
 */

int proc_fs(TSK_IMG_INFO * img_info, TSK_OFF_T start)
{
    TSK_FS_INFO *fs_info;
    u_int sector_size = img_info->sector_size;

    /* Try it as a file system */
    fs_info = tsk_fs_open_img(img_info, start, TSK_FS_TYPE_DETECT);
    if (fs_info == NULL) {
	comment("TSK_Error '%s' at sector %" PRIuDADDR " offset %" PRIuDADDR " sector_size=%u",
		tsk_error_get(),start/sector_size,start,sector_size);

	/* We could do some carving on the volume data at this point */
	return -1;
    }

    comment("fs start: %" PRIuDADDR, start);
    if(x){
	char buf[1024];
	snprintf(buf,sizeof(buf),"offset='%" PRIuDADDR "'",start);
	x->push("volume",buf);
    }

    current_partition_num++;
    current_partition_start = fs_info->offset;
    partition_info("partition_offset",fs_info->offset);

    /*Special Processing for FAT to report cluster and sector size*/
    if(TSK_FS_TYPE_ISFAT(fs_info->ftype))
    {
        partition_info("sector_size",((FATFS_INFO *)fs_info)->ssize);
        partition_info("block_size",((FATFS_INFO *)fs_info)->csize * ((FATFS_INFO *)fs_info)->ssize);
    }
    else
    {
        partition_info("block_size",fs_info->block_size);
    }

    partition_info("ftype",fs_info->ftype);
    partition_info("ftype_str",tsk_fs_type_toname(fs_info->ftype));
    partition_info("block_count",fs_info->block_count);
    partition_info("first_block",fs_info->first_block);
    partition_info("last_block",fs_info->last_block);
    if(t) fputc('\n',t);

    /* Walk the files, starting at the root directory */
    int dir_walk_flags = TSK_FS_DIR_WALK_FLAG_RECURSE | TSK_FS_DIR_WALK_FLAG_ALLOC;

    if(opt_allocated_only){
	dir_walk_flags |= TSK_FS_DIR_WALK_FLAG_NOORPHAN;
	partition_info("allocated_only",1);
    }
    else {
	dir_walk_flags |= TSK_FS_DIR_WALK_FLAG_UNALLOC;
    }

    int ret = 0;
    if (tsk_fs_dir_walk(fs_info, fs_info->root_inum,
			(TSK_FS_DIR_WALK_FLAG_ENUM) dir_walk_flags, dir_act, NULL)) {
	comment("TSK Error: tsk_fs_dir_walk: ",tsk_error_get());
	ret = -1;
    }
    else {
	/* We could do some analysis of unallocated blocks at this point...  */
	tsk_fs_close(fs_info);
    }
    if(x) x->pop();
    comment("end of volume");
    return ret;
}

/**
 * Volume system walk callback function that will analyze
 * each volume to find a file system.
 */
static TSK_WALK_RET_ENUM
vs_act(TSK_VS_INFO * vs_info, const TSK_VS_PART_INFO * vs_part, void *ptr)
{
    int *count = (int *)ptr;
    if (proc_fs(vs_info->img_info, vs_part->start * vs_info->block_size)) {
        // if we return ERROR here, then the walk will stop.  But, the
        // error could just be because we looked into an unallocated volume.
        // do any special error handling / reporting here.
        tsk_error_reset();
        return TSK_WALK_CONT;
    }

    (*count)++;
    return TSK_WALK_CONT;
}


/** proc_vs
 * Process the partition tables in the disk image pointed to by img.
 * File system analysis will be performed on each partition.
 *   mm_open() - opens partition
 *   mm_part_walk() - walks partition
 * If we can't open as a disk image, try to open as a raw file system
 *
 * @param img_info - the Image to process
 * @return -1 on error and 0 on success but nothing found, otherwise the number of file systems
 *             processed without error.
 */
int proc_vs(TSK_IMG_INFO * img_info)
{
    TSK_VS_INFO *vs_info;
    int start = 0;
    int count = 0;

    // USE mm_walk to get the volumes
    if ((vs_info = tsk_vs_open(img_info, start, TSK_VS_TYPE_DETECT)) == NULL) {

        /* There was no volume system, but there could be a file system.
	 * Look for one at well-known locations
	 */
        tsk_error_reset();
        if (proc_fs(img_info, 0)==0) return 1;
        tsk_error_reset();
	if (proc_fs(img_info, 63*512)==0) return 1;
        tsk_error_reset();

	/* Just try them all */
	for(int i=1;i<63;i++){
	    if(proc_fs(img_info,i*512)==0) return 1;
	    tsk_error_reset();
	}
	/* Give up */
	return -1;
    }
    else {
        if (tsk_verbose) fprintf(stderr, "Volume system open, examining each\n");

        /* Walk the allocated volumes (skip metadata and unallocated volumes) */
        if (tsk_vs_part_walk(vs_info, 0, vs_info->part_count-1,
                (TSK_VS_PART_FLAG_ENUM) (TSK_VS_PART_FLAG_ALLOC), vs_act, &count)) {
            tsk_vs_close(vs_info);
            return -1;
        }
        tsk_vs_close(vs_info);
    }
    return count;
}

void process_scalpel_audit_file(TSK_IMG_INFO *img_info,const char *audit_file)
{
    const char *fmt = "%12s%qd\t\t%3s%zd";
    FILE *f = fopen(audit_file,"r");
    while(!feof(f)){
	char buf[1024];
	while(fgets(buf,sizeof(buf),f)){
	    char filename[13];
	    int64_t start;
	    char chop[4];
	    size_t length;
	    memset(filename,0,sizeof(filename));
	    memset(chop,0,sizeof(chop));
	    if(sscanf(buf,fmt,filename,&start,chop,&length)==4){
		/* See if we can get the bytes */

		if(a) a->new_row();
		if(x) x->push("fileobject");

		content ci(img_info);
		ci.evidence_dirname = "?/";
		ci.set_filename(filename); // fictitious filename, but needed for plugins

		char *buf2 = (char *)calloc(length,1);
		size_t r2 = tsk_img_read(img_info,(TSK_OFF_T)start,buf2,length);

		file_info("filesize",r2);
		if(r2!=length){
		    file_info("carvelength",length);
		}

		ci.add_seg(start,start,0,r2,TSK_FS_BLOCK_FLAG_RAW,"");	// may not be able to read it all
		ci.add_bytes(buf2,0,r2);
		ci.write_record();
		free(buf2);

		/* END of file processing */

		if(x) x->pop();
		if(t) fputs("\n",t);
	    }
	}
    }
}

int process_image_file(int argc,char * const *argv,const char *audit_file,u_int sector_size)
{
    TSK_IMG_INFO *img_info;
    int count = 0;

    img_info = tsk_img_open_utf8(argc,(const char **)argv, TSK_IMG_TYPE_DETECT,sector_size);

    if (img_info==0){
	comment("TSK Error (img_open) %s sector_size=%u",tsk_error_get(),sector_size);
    } else {
	if(audit_file){
	    comment("audit file: %s",audit_file);
	    process_scalpel_audit_file(img_info,audit_file);
	}
	else{
	    if (opt_debug) printf("calling do_dimage()\n");

	    int r = proc_vs(img_info);
	    if (r<0){
		comment("TSK Error (do_dimage) %s",tsk_error_get());
	    }
	    if(r>0) count += r;
	}
	tsk_img_close(img_info);
    }
    return count;
}
