
#include "tsk3/tsk_tools_i.h"
#include "parent_tracker.h"
#include "fiwalk.h"


using namespace std;

#include <iostream>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <stack>
#include <list>





parent_tracker::parent_tracker(){
    this->flags=0;
}

int parent_tracker::process_dentry(const TSK_FS_DIR *dir,const TSK_FS_FILE *fs_file){
    TSK_FS_DIR *r_dir = NULL;

    printf("Dir names_used:%d names_alloc:%d\n", dir->names_used, dir->names_alloc);

    int dot_file = is_dot_or_double_dot(fs_file);
    printf("Dot File? %d, %d\n", dot_file, !dot_file);


    if(parent_stack.empty())
    {
        printf("\t\tDebug Stack was Empty doing a PUSH\n");
        if (fs_file->meta->addr != fs_file->fs_info->root_inum)
        {
            printf("\t\tDEBUG this inum is not the fs root pushing fs_root:\n");
            r_dir = tsk_fs_dir_open_meta(fs_file->fs_info,fs_file->fs_info->root_inum);
            if (r_dir == NULL)
                printf("\t\tDEBUG cannot open fs root\n");
            else
            {
                this->last_parent_inum=fs_file->fs_info->root_inum;
                this->add_pt_dentry_info(r_dir);
                this->stat_dentry_stack();
            }
        }
    }

    if (!dot_file)
    {
        printf("\tDEBUG NOT a dotfile\n");

        if(fs_file->meta->type & TSK_FS_META_TYPE_DIR)
        {
            this->inc_dentry_counter(&parent_stack.top());
            if(parent_stack.top().curr_entry == parent_stack.top().num_used_entries)
            {
                printf("\t DEBUG  Time To Pop?\n");
                rm_pt_dentry_info();
            }
            printf("\t\tDebug Directory Doing an Inc and Push\n");
            this->add_pt_dentry_info(dir);
        }
        else //if (dot_file)
        {
            printf("\t\tDebug Not a Directory doing an Inc \n");
            this->inc_dentry_counter(&parent_stack.top());
        }

        this->stat_dentry_stack();

    }else if(dot_file)
    {
        printf("\t DEBUG DOT FILE DOING AN INC\n");
        this->stat_dentry_stack();
        this->inc_dentry_counter(&parent_stack.top());
    }else
    {
        printf("\t DEBUG DEFAULT DOING AN INC\n");
        this->inc_dentry_counter(&parent_stack.top());
    }

    if(parent_stack.top().curr_entry == parent_stack.top().num_used_entries)
    {
        printf("\t DEBUG  Time To Pop?\n");
        rm_pt_dentry_info();
    }
    this->stat_dentry_stack();

    return 0;
}

int parent_tracker::inc_dentry_counter(PT_DENTRY_INFO * d_info)
{
    printf("Before: %d\t", d_info->curr_entry);
    d_info->curr_entry++;
    printf("After: %d\n", d_info->curr_entry);
    return 0;
}

int parent_tracker::dec_dentry_counter(PT_DENTRY_INFO * d_info)
{
    d_info->curr_entry++;
    return 0;
}

int parent_tracker::add_pt_dentry_info(const TSK_FS_DIR *dir){
    PT_DENTRY_INFO *d_info = new PT_DENTRY_INFO();
    PT_DENTRY_INFO *d_info2 = NULL;


    if (d_info == NULL)
        return 1;

    if (!parent_stack.empty())
        this->last_parent_inum = parent_stack.top().addr;

    d_info->num_entries = dir->names_alloc;
    d_info->num_used_entries = dir->names_used;
    d_info->addr = dir->addr;
    d_info->curr_entry = 0;

    this->parent_stack.push(*d_info);
    return 0;
}

int parent_tracker::rm_pt_dentry_info(){
    PT_DENTRY_INFO *d_info = NULL;
    d_info = &this->parent_stack.top();
    this->last_parent_inum=parent_stack.top().addr;
    this->parent_stack.pop();
    this->set_just_popped();
    this->stat_dentry_stack();
    //free(d_info);
    return 0;
}

int parent_tracker::stat_dentry_stack(){
    if (this->parent_stack.empty())
    {
        printf("Stack Empty\n");
        return 0;
    }
    PT_DENTRY_INFO *d_info = &parent_stack.top();
    printf("Stack Status: Empty %u, Size %u, Last_Parent: %u\n", parent_stack.empty(), parent_stack.size(), this->last_parent_inum);
    printf("TOP ENTRY: ADDR: %u, Allocated: %d, Used: %d, Current %d\n", d_info->addr, d_info->num_entries, d_info->num_used_entries, d_info->curr_entry);
    return 0;
}

int parent_tracker::is_dot_or_double_dot(const TSK_FS_FILE *fs_file){

//    printf("Is Dot: %d Is DoubleDot: %d\n", strcmp(fs_file->name->name,"."), strcmp(fs_file->name->name,"..")); //DEBUG
    if (strcmp(fs_file->name->name,".") == 0 || strcmp(fs_file->name->name,"..") == 0){
        return 1;
    }
    return 0;
}

int parent_tracker::print_parent(const TSK_FS_FILE *fs_file){
    if(fs_file->meta->type & TSK_FS_META_TYPE_DIR && !TSK_FS_ISDOT(fs_file->name->name))
        file_info("inode", this->last_parent_inum);
    else if(this->check_just_popped()){
        file_info("inode", this->last_parent_inum);
        this->clear_just_popped();
    }
    else
        file_info("inode",parent_stack.top().addr);
    return 0;
}

void parent_tracker::set_just_popped(){
    this->flags |= 0x1;
}

void parent_tracker::clear_just_popped(){
    this->flags &= 0xFE;
}

int parent_tracker::check_just_popped(){
    return this->flags & 0x1;
}

