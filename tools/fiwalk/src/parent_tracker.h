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

    uint64_t addr;               //inode_num
    uint64_t p_addr;        //Parent_address
    int num_entries;
    int num_used_entries;
    int curr_entry;
    uint32_t num_printed;
    uint8_t flags;

};

#define    PT_FLAG_JUST_POPPED  0x01
#define    PT_FLAG_DELAY_POP    0x02

#define    PT_DEBUG     0

class parent_tracker{
    private:
    std::list<int> child_list;
    std::deque<PT_DENTRY_INFO> parent_stack;
    int is_dot_or_double_dot(const TSK_FS_FILE *);
    int inc_dentry_counter(PT_DENTRY_INFO *);
    int dec_dentry_counter(PT_DENTRY_INFO *);
    void inc_dentry_print_count(PT_DENTRY_INFO *);
    uint8_t flags; //1=just_popped
    inline void set_flag(uint8_t);
    inline void clear_flag(uint8_t);
    inline int check_flag(uint8_t);
#if PT_DEBUG
    int stat_dentry_stack();
    int stat_dentry(PT_DENTRY_INFO *);
#endif
    public:

    parent_tracker();
    int print_parent(const TSK_FS_FILE *);
    int add_pt_dentry_info(const TSK_FS_DIR *);
    int rm_pt_dentry_info();

    int process_dentry(const TSK_FS_DIR *, const TSK_FS_FILE *);


};
#endif


#endif
