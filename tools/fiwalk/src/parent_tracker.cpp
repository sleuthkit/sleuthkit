
#include "tsk3/tsk_tools_i.h"
#include "parent_tracker.h"


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
    printf("Constructor\n");
}

int parent_tracker::process_dentry(const TSK_FS_DIR *dir,const TSK_FS_FILE *fs_file){
    printf("In Process_dentry\n");
    printf("Dir names_used:%d names_alloc:%d\n", dir->names_used, dir->names_alloc);

    int dot_file = is_dot_or_double_dot(fs_file);
    printf("Dot File? %d\n", dot_file);
    if (!dot_file || parent_stack.empty())
    {
        this->add_pt_dentry_info(dir);
        this->stat_dentry_stack();
  //      this->inc_dentry_counter(&parent_stack.top());

    }else if(dot_file)
    {
        this->stat_dentry_stack();
        this->inc_dentry_counter(&parent_stack.top());
    }
    this->stat_dentry_stack();
/*

    if(this->parent_stack.empty())
    {
        this->parent_stack.push(fs_file->fs_info->root_inum);
    }

    if(!this->parent_stack.empty())
    {
        printf("Current Parent %u, %u, %u\n", this->parent_stack.top(), this->parent_stack.size(), fs_file->meta->addr); //DEBUG
//DEBUG        printf("fs_file %p, %p\n", dir->fs_file, fs_file->name);
        if(fs_file->name == NULL || fs_file->name->name == NULL)
        {
            if (fs_file->name == NULL)
            {
                printf("fs_file->name is NULL\n");
                return 1;
            }
//DEBUG        printf("fs_file %p, %p/n", fs_file->name, fs_file->name->name);
        }
        else{
            printf("Dir_name: %s\n", fs_file->name->name);
            printf("Is Dot: %d Is DoubleDot: %d\n", strcmp(fs_file->name->name,"."), strcmp(fs_file->name->name,".."));
        }
    }
    if(this->parent_stack.top() != fs_file->meta->addr && !(strcmp(fs_file->name->name,".") == 0)  && !(strcmp(fs_file->name->name,"..") == 0))
    {
        this->parent_stack.push(fs_file->meta->addr);
        printf("Current Parent %u, %u\n", this->parent_stack.top(), this->parent_stack.size());
    }
*/
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
    PT_DENTRY_INFO *d_info = (PT_DENTRY_INFO *)malloc(sizeof(PT_DENTRY_INFO));

    if (d_info == NULL)
        return 1;
    d_info->num_entries = dir->names_alloc;
    d_info->num_used_entries = dir->names_used;
    d_info->addr = dir->addr;
    d_info->curr_entry = 0;

    this->parent_stack.push(*d_info);

    return 0;
}

int parent_tracker::stat_dentry_stack(){
    if (this->parent_stack.empty())
    {
        printf("Stack Empty\n");
        return 0;
    }
    PT_DENTRY_INFO *d_info = &parent_stack.top();
    printf("Stack Status: Empty %u, Size %u\n", parent_stack.empty(), parent_stack.size());
    printf("TOP ENTRY: ADDR: %u, Allocated: %d, Used: %d, Current %d\n", d_info->addr, d_info->num_entries, d_info->num_used_entries, d_info->curr_entry);
    return 0;
}

int parent_tracker::is_dot_or_double_dot(const TSK_FS_FILE *fs_file){

//DEBUG    printf("Is Dot: %d Is DoubleDot: %d\n", strcmp(fs_file->name->name,"."), strcmp(fs_file->name->name,"..")); //DEBUG
    if (strcmp(fs_file->name->name,".") == 0 || !strcmp(fs_file->name->name,"..") == 0){
        return 1;
    }
    return 0;
}
