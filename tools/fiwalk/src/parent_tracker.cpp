
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
            this->inc_dentry_counter(&parent_stack.back());
            if(parent_stack.back().curr_entry == parent_stack.back().num_used_entries)
            {
                printf("\t DEBUG  Last entry is a dir, delay popping me\n");
                parent_stack.back().flags |= PT_FLAG_DELAY_POP;
            }
            printf("\t\tDebug Directory Doing an Inc and Push\n");
            this->add_pt_dentry_info(dir);
        }
        else //if (dot_file)
        {
            printf("\t\tDebug Not a Directory doing an Inc \n");
            this->inc_dentry_counter(&parent_stack.back());
        }

        this->stat_dentry_stack();

    }
    else if(dot_file)
    {
        printf("\t DEBUG DOT FILE DOING AN INC\n");
        this->stat_dentry_stack();
        this->inc_dentry_counter(&parent_stack.back());
    }else
    {
        printf("\t DEBUG DEFAULT DOING AN INC\n");
        this->inc_dentry_counter(&parent_stack.back());
    }

 /*   if(parent_stack.top().curr_entry == parent_stack.top().num_used_entries)
    {
        printf("\t DEBUG  Time To Pop?\n");
        rm_pt_dentry_info();
    }
*/    this->stat_dentry_stack();

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

    if (d_info == NULL)
        return 1;

    if (!parent_stack.empty()){
        d_info->p_addr = parent_stack.back().addr;
    }
    else{
        d_info->p_addr = dir->addr;
    }
  
    d_info->num_entries = dir->names_alloc;
    d_info->num_used_entries = dir->names_used;
    d_info->addr = dir->addr;
    d_info->curr_entry = 0;
    

    this->parent_stack.push_back(*d_info);
//    printf("\t\tAdd_pt_dentry_info: %p->%p\n", &this->ptr_dent, this->ptr_dent);
//    printf("\t\tAdd_pt_dentry_info: %p->%p\n", &this->ptr_prev_dent, this->ptr_prev_dent);
    return 0;
}

int parent_tracker::rm_pt_dentry_info(){
    printf("\t\tDEBUG rm_pt_dentry_info Popping\n");
//    PT_DENTRY_INFO *d_info = NULL;
//    d_info = &this->parent_stack.top();
    this->parent_stack.pop_back();
    this->set_flag(PT_FLAG_JUST_POPPED);
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
    PT_DENTRY_INFO *d_info = &parent_stack.back();
    printf("Stack Status:\n\tEmpty %u, Size %u\n", parent_stack.empty(), parent_stack.size());
    stat_dentry(d_info);
    return 0;
}

int parent_tracker::stat_dentry(PT_DENTRY_INFO *d_info)
{
    printf("\tDentryStats: ADDR: %u,%u, Allocated: %d, Used: %d, Printed:%d, Current: %d\n ", 
    d_info->addr, d_info->p_addr, d_info->num_entries, d_info->num_used_entries, d_info->num_printed, d_info->curr_entry);
    
}

int parent_tracker::is_dot_or_double_dot(const TSK_FS_FILE *fs_file){

//    printf("Is Dot: %d Is DoubleDot: %d\n", strcmp(fs_file->name->name,"."), strcmp(fs_file->name->name,"..")); //DEBUG
    if (strcmp(fs_file->name->name,".") == 0 || strcmp(fs_file->name->name,"..") == 0){
        return 1;
    }
    return 0;
}

void  parent_tracker::inc_dentry_print_count(PT_DENTRY_INFO * d_info){
        d_info->num_printed++;
        return;
}

int parent_tracker::print_parent(const TSK_FS_FILE *fs_file){
    int stack_size = parent_stack.size();
    if(fs_file->meta->type & TSK_FS_META_TYPE_DIR && !TSK_FS_ISDOT(fs_file->name->name))
    {
        file_info("inode", parent_stack.back().p_addr);
        printf("\t\tDEBUG incrementing num_printed: \n");
        stat_dentry(&this->parent_stack.at(stack_size-2));
        inc_dentry_print_count(&parent_stack.at(stack_size-2));
        stat_dentry(&this->parent_stack.at(stack_size-2));
        stat_dentry_stack();
    }
    else if(this->check_flag(PT_FLAG_JUST_POPPED))
    {
        file_info("inode", parent_stack.back().addr);
        this->clear_flag(PT_FLAG_JUST_POPPED);
    }
    else
    {
        file_info("inode",parent_stack.back().addr);
        printf("\t\tDEBUG incrementing num_printed: ");
        inc_dentry_print_count(&parent_stack.back());
        stat_dentry_stack();
    }
    if (parent_stack.back().num_printed == parent_stack.back().num_used_entries)
    {
        if((parent_stack.back().flags & PT_FLAG_DELAY_POP)){
            parent_stack.back().flags & ~PT_FLAG_DELAY_POP;
        }
        else
        {
            printf("\t\tDEBUG Popping: ");
            while(parent_stack.back().num_printed == parent_stack.back().num_used_entries)
                rm_pt_dentry_info();
        }

        stat_dentry_stack();
    }
    return 0;
}

inline void parent_tracker::set_flag(uint8_t flag){
    this->flags |= flag;
}

inline void parent_tracker::clear_flag(uint8_t flag){
    this->flags &= flag;
}

inline int parent_tracker::check_flag(uint8_t flag){
    return this->flags & flag;
}

