#ifndef PARENT_TRACKER_H
#define PARENT_TRACKER_H

/*
    Logic for keeping track of directory parents and children
    Necessary for systems that do not have pointer in the child back to the parent
*/

#ifdef __cplusplus
#include <list>
#include <stack>

class PT_DENTRY_INFO{
    public:

    int addr;               //inode_num
    int num_entries;
    int num_used_entries;
    int curr_entry;
};

class parent_tracker{
    private:
    std::list<int> child_list;
    std::stack<PT_DENTRY_INFO> parent_stack;
    int is_dot_or_double_dot(const TSK_FS_FILE *);
    int inc_dentry_counter(PT_DENTRY_INFO *);
    int dec_dentry_counter(PT_DENTRY_INFO *);
    uint64_t last_parent_inum;
    uint8_t flags; //1=just_popped
    void set_just_popped();
    void clear_just_popped();
    int check_just_popped();

    public:

    parent_tracker();
    int print_parent(const TSK_FS_FILE *);
    int add_pt_dentry_info(const TSK_FS_DIR *);
    int rm_pt_dentry_info();
    int stat_dentry_stack();

    int process_dentry(const TSK_FS_DIR *, const TSK_FS_FILE *);


};
#endif


#endif
