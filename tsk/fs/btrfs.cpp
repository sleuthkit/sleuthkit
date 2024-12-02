/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2015 Stefan Pöschel.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
*/

/**
 * \file btrfs.cpp
 * Contains the internal TSK Btrfs file system functions
 */

#include "tsk_fs_i.h"
#include "tsk_btrfs.h"
#include <cassert>



/*
 * general stuff
 */

// enable for debug messages
//#define BTRFS_DEBUG

// enable to also check tree node checksums (otherwise only the superblock checksum is checked)
#define BTRFS_CHECK_TREENODE_CSUM

// size of treenode cache
#define BTRFS_TREENODE_CACHE_SIZE 50



#ifdef BTRFS_DEBUG
#define BTRFS_DEBUG_PRINT 1
#else
#define BTRFS_DEBUG_PRINT 0
#endif

#define btrfs_debug(format, ...) \
    do { if (BTRFS_DEBUG_PRINT) tsk_fprintf(stderr, "[btrfs] " format, ##__VA_ARGS__); } while (0)


#if 0
static void
btrfs_debug_hexdump(const uint8_t * data, const int len,
    const char *caption)
{
    if (caption)
        tsk_fprintf(stderr, "----- Hexdump of '%s' (%d bytes) -----", caption, len);
    for (int i = 0; i < len; i++) {
        if (i % 24 == 0)
            tsk_fprintf(stderr, "\n 0x%04x", i);
        tsk_fprintf(stderr, " %02x", *(data + i));
    }
    tsk_fprintf(stderr, "\n");
}
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif




/**
 * Resets error and sets error number/string
 * @param a_errno error number
 * @param a_format error string
 */
static void
btrfs_error(const uint32_t a_errno, const char *a_format, ...)
{
    tsk_error_reset();
    tsk_error_set_errno(a_errno);

    va_list args;
    va_start(args, a_format);
    tsk_error_vset_errstr(a_format, args);
    va_end(args);
}






/*
 * structure parsing
 */


static void
btrfs_key_rawparse(const uint8_t * a_raw, BTRFS_KEY * a_key)
{
    a_key->object_id    = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x00);
    a_key->item_type    = a_raw[0x08];
    a_key->offset       = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x09);
}


static void
btrfs_time_rawparse(const uint8_t * a_raw, BTRFS_TIME * a_time)
{
    a_time->seconds     = tsk_gets64(BTRFS_ENDIAN, a_raw + 0x00);
    a_time->nanoseconds = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x08);
}


static void
btrfs_inode_rawparse(const uint8_t * a_raw, BTRFS_INODE_ITEM * a_ii)
{
    a_ii->generation        = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x00);
    a_ii->transid           = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x08);
    a_ii->size              = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x10);
    a_ii->blocks            = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x18);
    a_ii->block_group       = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x20);
    a_ii->nlink             = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x28);
    a_ii->uid               = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x2C);
    a_ii->gid               = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x30);
    a_ii->mode              = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x34);
    a_ii->rdev              = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x38);
    a_ii->flags             = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x40);
    a_ii->sequence          = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x48);
    memcpy(a_ii->_reserved  , a_raw + 0x50, sizeof(a_ii->_reserved));
    btrfs_time_rawparse(a_raw + 0x70, &a_ii->atime);
    btrfs_time_rawparse(a_raw + 0x7C, &a_ii->ctime);
    btrfs_time_rawparse(a_raw + 0x88, &a_ii->mtime);
    btrfs_time_rawparse(a_raw + 0x94, &a_ii->otime);
}


static void
btrfs_root_item_rawparse(const uint8_t * a_raw, BTRFS_ROOT_ITEM * a_ri)
{
    btrfs_inode_rawparse(a_raw + 0x00, &a_ri->inode);
    a_ri->expected_generation       = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xA0);
    a_ri->root_dir_object_id        = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xA8);
    a_ri->root_node_block_number    = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xB0);
    a_ri->byte_limit                = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xB8);
    a_ri->bytes_used                = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xC0);
    a_ri->last_snapshot_generation  = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xC8);
    a_ri->flags                     = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xD0);
    a_ri->number_of_references      = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xD8);
    btrfs_key_rawparse(a_raw + 0xDC, &a_ri->drop_progress);
    a_ri->drop_level                = a_raw[0xED];
    a_ri->root_node_level           = a_raw[0xEE];
}


static void
btrfs_dev_item_rawparse(const uint8_t * a_raw, BTRFS_DEV_ITEM * a_di)
{
    a_di->device_id             = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x00);
    a_di->total_bytes           = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x08);
    a_di->bytes_used            = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x10);
    a_di->optimal_io_align      = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x18);
    a_di->optimal_io_width      = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x1C);
    a_di->minimal_io_size       = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x20);
    a_di->type                  = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x24);
    a_di->generation            = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x2C);
    a_di->start_offset          = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x34);
    a_di->dev_group             = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x3C);
    a_di->seek_speed            = a_raw[0x40];
    a_di->bandwidth             = a_raw[0x41];
    memcpy(a_di->device_uuid    , a_raw + 0x42, sizeof(a_di->device_uuid));
    memcpy(a_di->fs_uuid        , a_raw + 0x52, sizeof(a_di->fs_uuid));
}


#ifdef BTRFS_DEBUG
static BTRFS_INODE_REF *
btrfs_inode_ref_fromraw(const uint8_t * a_raw, const uint32_t a_len)
{
    BTRFS_INODE_REF *result = NULL;
    BTRFS_INODE_REF *prev_ir = NULL;
    for (uint32_t offset = 0; offset < a_len;) {
        BTRFS_INODE_REF *curr_ir = new BTRFS_INODE_REF;
        if (prev_ir)
            prev_ir->next = curr_ir;
        else
            result = curr_ir;

        curr_ir->index_in_dir       = tsk_getu64(BTRFS_ENDIAN, a_raw + offset + 0x00);
        uint16_t name_len           = tsk_getu16(BTRFS_ENDIAN, a_raw + offset + 0x08);

        curr_ir->name_in_dir = new char[name_len + 1];
        memcpy(curr_ir->name_in_dir , a_raw + offset + 0x0A, name_len);
        curr_ir->name_in_dir[name_len] = 0x00;  // terminator

        offset += 10 + name_len;
        prev_ir = curr_ir;
    }
    if (prev_ir)
        prev_ir->next = NULL;
    return result;
}
#endif


#ifdef BTRFS_DEBUG
static void
btrfs_inode_ref_free(BTRFS_INODE_REF * a_ir)
{
    BTRFS_INODE_REF *old_ir;
    while (a_ir) {
        old_ir = a_ir;
        a_ir = a_ir->next;

        delete[] old_ir->name_in_dir;
        delete old_ir;
    }
}
#endif


static inline int
btrfs_dir_entry_single_rawlen(const uint8_t * a_raw)
{
    return 0x1E + tsk_getu16(BTRFS_ENDIAN, a_raw + 0x19) + tsk_getu16(BTRFS_ENDIAN, a_raw + 0x1B);
}

static BTRFS_DIR_ENTRY *
btrfs_dir_entry_fromraw_single(const uint8_t * a_raw)
{
    BTRFS_DIR_ENTRY *de = new BTRFS_DIR_ENTRY;
    // de->next must be set later!

    btrfs_key_rawparse(a_raw + 0x00, &de->child);
    de->transid         = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x11);
    de->data_len        = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x19);
    uint16_t name_len   = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x1B);
    de->type            = a_raw[0x1D];

    de->name = new char[name_len + 1];
    memcpy(de->name     , a_raw + 0x1E, name_len);
    de->name[name_len] = 0x00;  // terminator

    de->data = new uint8_t[de->data_len];
    memcpy(de->data     , a_raw + 0x1E + name_len, de->data_len);

    return de;
}

static BTRFS_DIR_ENTRY *
btrfs_dir_entry_fromraw(const uint8_t * a_raw, const uint32_t a_len)
{
    BTRFS_DIR_ENTRY *first_de = NULL;
    BTRFS_DIR_ENTRY *prev_de = NULL;

    for (const uint8_t *p = a_raw; p < a_raw + a_len; p += btrfs_dir_entry_single_rawlen(p)) {
        BTRFS_DIR_ENTRY *curr_de = btrfs_dir_entry_fromraw_single(p);

        if (!first_de)
            first_de = curr_de;

        if (prev_de)
            prev_de->next = curr_de;
        prev_de = curr_de;
    }
    prev_de->next = NULL;

    return first_de;
}


static void
btrfs_dir_entry_free(BTRFS_DIR_ENTRY * a_de)
{
    while (a_de) {
        BTRFS_DIR_ENTRY *next_de = a_de->next;
        delete[] a_de->name;
        delete[] a_de->data;

        delete a_de;

        a_de = next_de;
    }
}


static void
btrfs_extent_data_free(BTRFS_EXTENT_DATA * a_ed)
{
    if (!a_ed)
        return;

    if (a_ed->type == BTRFS_EXTENT_DATA_TYPE_INLINE)
        delete[] a_ed->rd.data;

    delete a_ed;
}


static BTRFS_EXTENT_DATA *
btrfs_extent_data_fromraw(const uint8_t * a_raw, const uint32_t a_len)
{
    BTRFS_EXTENT_DATA *ed = new BTRFS_EXTENT_DATA;

    ed->generation      = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x00);
    ed->size_decoded    = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x08);
    ed->compression     = a_raw[0x10];
    ed->encryption      = a_raw[0x11];
    ed->other_encoding  = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x12);
    ed->type            = a_raw[0x14];

    switch (ed->type) {
    case BTRFS_EXTENT_DATA_TYPE_INLINE:
        ed->rd.data_len = a_len - 0x15;
        ed->rd.data = new uint8_t[ed->rd.data_len];
        memcpy(ed->rd.data      , a_raw + 0x15, ed->rd.data_len);
        return ed;
    case BTRFS_EXTENT_DATA_TYPE_REGULAR:
    case BTRFS_EXTENT_DATA_TYPE_PREALLOC:
        ed->nrd.extent_address  = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x15);
        ed->nrd.extent_size     = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x1D);
        ed->nrd.file_offset     = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x25);
        ed->nrd.file_bytes      = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x2D);
        return ed;
    }

    btrfs_error(TSK_ERR_FS_INODE_COR, "btrfs_extent_data_fromraw: unknown type");
    btrfs_extent_data_free(ed);
    return NULL;
}


static uint64_t
btrfs_extent_data_size(BTRFS_EXTENT_DATA * a_ed)
{
    return a_ed->type == BTRFS_EXTENT_DATA_TYPE_INLINE ? a_ed->size_decoded : a_ed->nrd.file_bytes;
}


static void
btrfs_extent_item_rawparse(const uint8_t * a_raw, BTRFS_EXTENT_ITEM * a_ei)
{
    a_ei->reference_count   = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x00);
    a_ei->generation        = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x08);
    a_ei->flags             = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x10);
    // depending on the flags, different fields follow - ATM they are not needed and therefore ignored
}


static void
btrfs_chunk_item_stripe_rawparse(const uint8_t * a_raw,
    BTRFS_CHUNK_ITEM_STRIPE * a_cis)
{
    a_cis->device_id            = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x00);
    a_cis->offset               = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x08);
    memcpy(a_cis->device_uuid   , a_raw + 0x10, sizeof(a_cis->device_uuid));
}


static void
btrfs_chunk_item_free(BTRFS_CHUNK_ITEM * a_ci)
{
    if (!a_ci)
        return;

    delete[] a_ci->stripes;
    delete a_ci;
}

static int
btrfs_chunk_item_rawlen(const uint8_t * a_raw)
{
    return 0x30 + tsk_getu16(BTRFS_ENDIAN, a_raw + 0x2C) * 0x20;
}

static BTRFS_CHUNK_ITEM *
btrfs_chunk_item_fromraw(const uint8_t * a_raw)
{
    BTRFS_CHUNK_ITEM *ci = new BTRFS_CHUNK_ITEM;

    ci->chunk_size          = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x00);
    ci->referencing_root    = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x08);
    ci->stripe_length       = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x10);
    ci->type                = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x18);
    ci->optimal_io_align    = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x20);
    ci->optimal_io_width    = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x24);
    ci->minimal_io_size     = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x28);
    ci->number_of_stripes   = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x2C);
    ci->sub_stripes         = tsk_getu16(BTRFS_ENDIAN, a_raw + 0x2E);

    ci->stripes = new BTRFS_CHUNK_ITEM_STRIPE[ci->number_of_stripes];

    for (uint16_t i = 0; i < ci->number_of_stripes; i++)
        btrfs_chunk_item_stripe_rawparse(a_raw + 0x30 + i * 0x20, &ci->stripes[i]);

    return ci;
}


static void
btrfs_superblock_rawparse(const uint8_t * a_raw, BTRFS_SUPERBLOCK * a_sb)
{
    // csum ignored (checked on raw item)
    memcpy(a_sb->uuid           , a_raw + 0x20, sizeof(a_sb->uuid));
    a_sb->physical_address      = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x30);
    a_sb->flags                 = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x38);
    // magic ignored (checked on raw item)
    a_sb->generation            = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x48);
    a_sb->root_tree_root        = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x50);
    a_sb->chunk_tree_root       = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x58);
    a_sb->log_tree_root         = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x60);
    a_sb->log_root_transid      = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x68);
    a_sb->total_bytes           = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x70);
    a_sb->bytes_used            = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x78);
    a_sb->root_dir_objectid     = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x80);
    a_sb->num_devices           = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x88);
    a_sb->sectorsize            = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x90);
    a_sb->nodesize              = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x94);
    a_sb->leafsize              = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x98);
    a_sb->stripesize            = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x9C);
    a_sb->n                     = tsk_getu32(BTRFS_ENDIAN, a_raw + 0xA0);
    a_sb->chunk_root_generation = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xA4);
    a_sb->compat_flags          = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xAC);
    a_sb->compat_ro_flags       = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xB4);
    a_sb->incompat_flags        = tsk_getu64(BTRFS_ENDIAN, a_raw + 0xBC);
    a_sb->csum_type             = tsk_getu16(BTRFS_ENDIAN, a_raw + 0xC4);
    a_sb->root_level            = a_raw[0xC6];
    a_sb->chunk_root_level      = a_raw[0xC7];
    a_sb->log_root_level        = a_raw[0xC8];
    btrfs_dev_item_rawparse(a_raw + 0xC9, &a_sb->dev_item);
    memcpy(a_sb->label          , a_raw + 0x12B, sizeof(a_sb->label));
    memcpy(a_sb->reserved       , a_raw + 0x22B, sizeof(a_sb->reserved));
    memcpy(a_sb->system_chunks  , a_raw + 0x32B, sizeof(a_sb->system_chunks));
    memcpy(a_sb->_unused        , a_raw + 0xB2B, sizeof(a_sb->_unused));
}


static void
btrfs_key_pointer_rest_rawparse(const uint8_t * a_raw,
    BTRFS_KEY_POINTER_REST * a_kp)
{
    a_kp->block_number  = tsk_getu64(BTRFS_ENDIAN, a_raw + (0x11 - BTRFS_KEY_RAWLEN));
    a_kp->generation    = tsk_getu64(BTRFS_ENDIAN, a_raw + (0x19 - BTRFS_KEY_RAWLEN));
}


static void
btrfs_item_rest_rawparse(const uint8_t * a_raw, BTRFS_ITEM_REST * a_item)
{
    a_item->data_offset = tsk_getu32(BTRFS_ENDIAN, a_raw + (0x11 - BTRFS_KEY_RAWLEN));
    a_item->data_size   = tsk_getu32(BTRFS_ENDIAN, a_raw + (0x15 - BTRFS_KEY_RAWLEN));
}


static void
btrfs_tree_header_rawparse(const uint8_t * a_raw, BTRFS_TREE_HEADER * a_th)
{
    // csum ignored (checked on raw item)
    memcpy(a_th->uuid               , a_raw + 0x20, sizeof(a_th->uuid));
    a_th->logical_address           = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x30);
    a_th->flags                     = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x38) & 0x00FFFFFFFFFFFFFF;  // 7 bytes
    a_th->backref_rev               = a_raw[0x3F];
    memcpy(a_th->chunk_tree_uuid    , a_raw + 0x40, sizeof(a_th->chunk_tree_uuid));
    a_th->generation                = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x50);
    a_th->parent_tree_id            = tsk_getu64(BTRFS_ENDIAN, a_raw + 0x58);
    a_th->number_of_items           = tsk_getu32(BTRFS_ENDIAN, a_raw + 0x60);
    a_th->level                     = a_raw[0x64];
}



/*
 * structure printing
 */


#ifdef BTRFS_DEBUG
static inline const char *
btrfs_decode_item_type(const uint8_t a_item_type)
{
    switch (a_item_type) {
    case BTRFS_ITEM_TYPE_INODE_ITEM:
        return "INODE_ITEM";
    case BTRFS_ITEM_TYPE_INODE_REF:
        return "INODE_REF";
    case BTRFS_ITEM_TYPE_DIR_ITEM:
        return "DIR_ITEM";
    case BTRFS_ITEM_TYPE_DIR_INDEX:
        return "DIR_INDEX";
    case BTRFS_ITEM_TYPE_EXTENT_DATA:
        return "EXTENT_DATA";
    case BTRFS_ITEM_TYPE_ROOT_ITEM:
        return "ROOT_ITEM";
    case BTRFS_ITEM_TYPE_EXTENT_ITEM:
        return "EXTENT_ITEM";
    case BTRFS_ITEM_TYPE_METADATA_ITEM:
        return "METADATA_ITEM";
    case BTRFS_ITEM_TYPE_DEV_ITEM:
        return "DEV_ITEM";
    case BTRFS_ITEM_TYPE_CHUNK_ITEM:
        return "CHUNK_ITEM";
    default:
        return "(unknown)";
    }
}
#endif


#ifdef BTRFS_DEBUG
static void
btrfs_key_debugprint(const BTRFS_KEY * a_key)
{
    btrfs_debug("key: object ID/item type/offset: 0x%16" PRIx64 " / 0x%02" PRIx8 " / 0x%16" PRIx64 " = %s\n",
            a_key->object_id, a_key->item_type, a_key->offset, btrfs_decode_item_type(a_key->item_type));
}


static void
btrfs_time_debugprint(const BTRFS_TIME * a_time)
{
    btrfs_debug("time: seconds/nanoseconds: %" PRId64 " / %" PRId32 "\n", a_time->seconds, a_time->nanoseconds);
}


static void
btrfs_inode_debugprint(const BTRFS_INODE_ITEM * a_ii)
{
    btrfs_debug("inode: generation:  %"         PRId64 "\n", a_ii->generation);
    btrfs_debug("inode: transid:     %"         PRId64 "\n", a_ii->transid);
    btrfs_debug("inode: size:        %"         PRId64 "\n", a_ii->size);
    btrfs_debug("inode: blocks:      %"         PRId64 "\n", a_ii->blocks);
    btrfs_debug("inode: block group: %"         PRId64 "\n", a_ii->block_group);
    btrfs_debug("inode: nlink:       %"         PRId32 "\n", a_ii->nlink);
    btrfs_debug("inode: uid:         %"         PRId32 "\n", a_ii->uid);
    btrfs_debug("inode: gid:         %"         PRId32 "\n", a_ii->gid);
    btrfs_debug("inode: mode:        0x%08"     PRIx32 "\n", a_ii->mode);
    btrfs_debug("inode: rdev:        0x%"       PRIx64 "\n", a_ii->rdev);
    btrfs_debug("inode: flags:       0x%016"    PRIx64 "\n", a_ii->flags);
    btrfs_debug("inode: sequence:    %"         PRId64 "\n", a_ii->sequence);
    btrfs_time_debugprint(&a_ii->atime);
    btrfs_time_debugprint(&a_ii->ctime);
    btrfs_time_debugprint(&a_ii->mtime);
    btrfs_time_debugprint(&a_ii->otime);
}


static void
btrfs_root_item_debugprint(const BTRFS_ROOT_ITEM * a_ri)
{
    btrfs_inode_debugprint(&a_ri->inode);
    btrfs_debug("root item: expected generation:      %"        PRId64 "\n", a_ri->expected_generation);
    btrfs_debug("root item: root dir object ID:       0x%"      PRIx64 "\n", a_ri->root_dir_object_id);
    btrfs_debug("root item: root node block number:   0x%"      PRIx64 "\n", a_ri->root_node_block_number);
    btrfs_debug("root item: byte limit:               %"        PRId64 "\n", a_ri->byte_limit);
    btrfs_debug("root item: bytes used:               %"        PRId64 "\n", a_ri->bytes_used);
    btrfs_debug("root item: last snapshot generation: %"        PRId64 "\n", a_ri->last_snapshot_generation);
    btrfs_debug("root item: flags:                    0x%016"   PRIx64 "\n", a_ri->flags);
    btrfs_debug("root item: number of references:     %"        PRId32 "\n", a_ri->number_of_references);
    btrfs_key_debugprint(&a_ri->drop_progress);
    btrfs_debug("root item: drop level:               %"        PRId8  "\n", a_ri->drop_level);
    btrfs_debug("root item: root node level:          %"        PRId8  "\n", a_ri->root_node_level);
}


static void
btrfs_dev_item_debugprint(const BTRFS_DEV_ITEM * a_di)
{
    btrfs_debug("dev item: device_id:        %"     PRId64 "\n", a_di->device_id);
    btrfs_debug("dev item: total bytes:      %"     PRId64 "\n", a_di->total_bytes);
    btrfs_debug("dev item: bytes used:       %"     PRId64 "\n", a_di->bytes_used);
    btrfs_debug("dev item: optimal_io_align: 0x%"   PRIx32 "\n", a_di->optimal_io_align);
    btrfs_debug("dev item: optimal_io_width: 0x%"   PRIx32 "\n", a_di->optimal_io_width);
    btrfs_debug("dev item: minimal_io_size:  0x%"   PRIx32 "\n", a_di->minimal_io_size);
    btrfs_debug("dev item: type:             0x%"   PRIx64 "\n", a_di->type);
    btrfs_debug("dev item: generation:       %"     PRId64 "\n", a_di->generation);
    btrfs_debug("dev item: start_offset:     0x%"   PRIx64 "\n", a_di->start_offset);
    btrfs_debug("dev item: dev_group:        0x%"   PRIx32 "\n", a_di->dev_group);
    btrfs_debug("dev item: seek_speed:       %"     PRId8  "\n", a_di->seek_speed);
    btrfs_debug("dev item: bandwidth:        %"     PRId8  "\n", a_di->bandwidth);
}


static void
btrfs_inode_ref_debugprint(BTRFS_INODE_REF * a_ir)
{
    for (int index = 0; a_ir; index++) {
        btrfs_debug("inode ref #%d: index in dir: %"    PRId64  "\n", index, a_ir->index_in_dir);
        btrfs_debug("inode ref #%d: name in dir:  '%s'"         "\n", index, a_ir->name_in_dir);
        a_ir = a_ir->next;
    }
}


static void
btrfs_dir_entry_debugprint(BTRFS_DIR_ENTRY * a_de)
{
    for (int index = 0; a_de; index++) {
        btrfs_key_debugprint(&a_de->child);
        btrfs_debug("dir entry #%d: transid:  %"    PRId64  "\n", index, a_de->transid);
        btrfs_debug("dir entry #%d: type:     %"    PRId8   "\n", index, a_de->type);
        btrfs_debug("dir entry #%d: name:     '%s'"         "\n", index, a_de->name);
        btrfs_debug("dir entry #%d: data_len: %"    PRId16  "\n", index, a_de->data_len);
        a_de = a_de->next;
    }
}


static void
btrfs_extent_data_debugprint(const BTRFS_EXTENT_DATA * a_ed)
{
    btrfs_debug("extent data: generation:     %"        PRId64  "\n", a_ed->generation);
    btrfs_debug("extent data: size_decoded:   %"        PRId64  "\n", a_ed->size_decoded);
    btrfs_debug("extent data: compression:    0x%02"    PRIx8   "\n", a_ed->compression);
    btrfs_debug("extent data: encryption:     0x%02"    PRIx8   "\n", a_ed->encryption);
    btrfs_debug("extent data: other_encoding: 0x%04"    PRIx16  "\n", a_ed->other_encoding);
    btrfs_debug("extent data: type:           0x%02"    PRIx8   "\n", a_ed->type);

    switch (a_ed->type) {
    case BTRFS_EXTENT_DATA_TYPE_INLINE:
        btrfs_debug("extent data: resident data_len: %" PRId32 "\n", a_ed->rd.data_len);
        break;
    case BTRFS_EXTENT_DATA_TYPE_REGULAR:
    case BTRFS_EXTENT_DATA_TYPE_PREALLOC:
        btrfs_debug("extent data: non-resident extent address: 0x%" PRIx64 "\n", a_ed->nrd.extent_address);
        btrfs_debug("extent data: non-resident extent size:    %"   PRId64 "\n", a_ed->nrd.extent_size);
        btrfs_debug("extent data: non-resident file offset:    0x%" PRIx64 "\n", a_ed->nrd.file_offset);
        btrfs_debug("extent data: non-resident file size:      %"   PRId64 "\n", a_ed->nrd.file_bytes);
        break;
    default:
        btrfs_debug("extent data: - unknown type -\n");
    }
}


static void
btrfs_extent_item_debugprint(const BTRFS_EXTENT_ITEM * a_ei)
{
    btrfs_debug("extent item: reference count: %"       PRId64 "\n", a_ei->reference_count);
    btrfs_debug("extent item: generation:      %"       PRId64 "\n", a_ei->generation);
    btrfs_debug("extent item: flags:           0x%016"  PRIx64 "\n", a_ei->flags);
}


static void
btrfs_chunk_item_debugprint(const BTRFS_CHUNK_ITEM * a_ci)
{
    btrfs_debug("chunk item: chunk size:        0x%"    PRIx64 "\n", a_ci->chunk_size);
    btrfs_debug("chunk item: referencing root:  0x%"    PRIx64 "\n", a_ci->referencing_root);
    btrfs_debug("chunk item: stripe length:     0x%"    PRIx64 "\n", a_ci->stripe_length);
    btrfs_debug("chunk item: type:              0x%"    PRIx64 "\n", a_ci->type);
    btrfs_debug("chunk item: optimal_io_align:  0x%"    PRIx32 "\n", a_ci->optimal_io_align);
    btrfs_debug("chunk item: optimal_io_width:  0x%"    PRIx32 "\n", a_ci->optimal_io_width);
    btrfs_debug("chunk item: minimal_io_size:   0x%"    PRIx32 "\n", a_ci->minimal_io_size);
    btrfs_debug("chunk item: sub stripes:       %"      PRId16 "\n", a_ci->sub_stripes);

    for (uint16_t index = 0; index < a_ci->number_of_stripes; index++) {
        BTRFS_CHUNK_ITEM_STRIPE *a_cis = &a_ci->stripes[index];
        btrfs_debug("chunk item stripe #%d: device_id: %"   PRId64 "\n", index, a_cis->device_id);
        btrfs_debug("chunk item stripe #%d: offset:    0x%" PRIx64 "\n", index, a_cis->offset);
    }
}


static void
btrfs_superblock_debugprint(const BTRFS_SUPERBLOCK * a_sb)
{
    btrfs_debug("superblock: physical address:      0x%"    PRIx64 "\n", a_sb->physical_address);
    btrfs_debug("superblock: flags:                 0x%016" PRIx64 "\n", a_sb->flags);
    btrfs_debug("superblock: generation:            %"      PRId64 "\n", a_sb->generation);
    btrfs_debug("superblock: root tree root:        0x%"    PRIx64 "\n", a_sb->root_tree_root);
    btrfs_debug("superblock: chunk tree root:       0x%"    PRIx64 "\n", a_sb->chunk_tree_root);
    btrfs_debug("superblock: log tree root:         0x%"    PRIx64 "\n", a_sb->log_tree_root);
    btrfs_debug("superblock: log_root_transid:      0x%"    PRIx64 "\n", a_sb->log_root_transid);
    btrfs_debug("superblock: total bytes:           %"      PRId64 "\n", a_sb->total_bytes);
    btrfs_debug("superblock: bytes used:            %"      PRId64 "\n", a_sb->bytes_used);
    btrfs_debug("superblock: root_dir_objectid:     0x%"    PRIx64 "\n", a_sb->root_dir_objectid);
    btrfs_debug("superblock: num_devices:           %"      PRId64 "\n", a_sb->num_devices);
    btrfs_debug("superblock: sectorsize:            %"      PRId32 "\n", a_sb->sectorsize);
    btrfs_debug("superblock: nodesize:              %"      PRId32 "\n", a_sb->nodesize);
    btrfs_debug("superblock: leafsize:              %"      PRId32 "\n", a_sb->leafsize);
    btrfs_debug("superblock: stripesize:            %"      PRId32 "\n", a_sb->stripesize);
    btrfs_debug("superblock: n:                     %"      PRId32 "\n", a_sb->n);
    btrfs_debug("superblock: chunk_root_generation: %"      PRId64 "\n", a_sb->chunk_root_generation);
    btrfs_debug("superblock: compat_flags:          0x%016" PRIx64 "\n", a_sb->compat_flags);
    btrfs_debug("superblock: compat_ro_flags:       0x%016" PRIx64 "\n", a_sb->compat_ro_flags);
    btrfs_debug("superblock: incompat_flags:        0x%016" PRIx64 "\n", a_sb->incompat_flags);
    btrfs_debug("superblock: csum_type:             %"      PRId16 "\n", a_sb->csum_type);
    btrfs_debug("superblock: root_level:            %"      PRId8  "\n", a_sb->root_level);
    btrfs_debug("superblock: chunk_root_level:      %"      PRId8  "\n", a_sb->chunk_root_level);
    btrfs_debug("superblock: log_root_level:        %"      PRId8  "\n", a_sb->log_root_level);
    btrfs_dev_item_debugprint(&a_sb->dev_item);
    btrfs_debug("superblock: label:                 '%s'\n"            , a_sb->label);
//  btrfs_debug_hexdump(a_sb->system_chunks, a_sb->n, "SYSTEM chunks");
}


static void
btrfs_key_pointer_rest_debugprint(const BTRFS_KEY_POINTER_REST * a_kp)
{
    btrfs_debug("key pointer: block number: 0x%"    PRIx64 "\n", a_kp->block_number);
    btrfs_debug("key pointer: generation:   %"      PRId64 "\n", a_kp->generation);
}


static void
btrfs_item_rest_debugprint(const BTRFS_ITEM_REST * a_item)
{
    btrfs_debug("item: data offset: %"  PRId32 "\n", a_item->data_offset);
    btrfs_debug("item: data size:   %"  PRId32 "\n", a_item->data_size);
}


static void
btrfs_tree_header_debugprint(const BTRFS_TREE_HEADER * a_th)
{
    btrfs_debug("tree header: logical address: 0x%"     PRIx64 "\n", a_th->logical_address);
    btrfs_debug("tree header: flags:           0x%014"  PRIx64 "\n", a_th->flags);  // 7 bytes
    btrfs_debug("tree header: backref_rev:     %"       PRId8  "\n", a_th->backref_rev);
    btrfs_debug("tree header: generation:      %"       PRId64 "\n", a_th->generation);
    btrfs_debug("tree header: parent_tree_id:  0x%"     PRIx64 "\n", a_th->parent_tree_id);
    btrfs_debug("tree header: number_of_items: %"       PRId32 "\n", a_th->number_of_items);
    btrfs_debug("tree header: level:           %"       PRId8  "\n", a_th->level);
}
#endif



/*
 * checksums
 */


/**
 * Checks if the specified checksum type is supported.
 * @param a_csum_type checksum type
 * @return true if supported, otherwise false
 */
static bool
btrfs_csum_supported(const uint16_t a_csum_type)
{
    switch (a_csum_type) {
    case BTRFS_CSUM_TYPE_CRC32C:
        // CRC-32C
        return true;
    }
    return false;
}


/**
 * Returns a string description of the specified checksum type.
 * @param a_csum_type checksum type
 * @return description
 */
static const char *
btrfs_csum_description(const uint16_t a_csum_type)
{
    switch (a_csum_type) {
    case BTRFS_CSUM_TYPE_CRC32C:
        // CRC-32C
        return "CRC-32C";
    }
    return "unknown";
}


/**
 * Validates the checksum of a specific amount of data.
 * @param a_csum_type checksum type (must be supported)
 * @param a_data pointer to data
 * @param a_len data len
 * @return true if the checksum is valid, otherwise false
 *
 * It looks like the BTRFS checksums start with the checksum and are then followed by the data being summed.
 * So if the data size is < BTRFS_CSUM_RAWLEN, the checksum cannot be valid
 */
static bool
btrfs_csum_valid(const uint16_t a_csum_type, const uint8_t * a_data,
    const int a_len)
{
#ifdef BTRFS_DEBUG
    btrfs_debug("btrfs_csum_valid a_csum_type=%d BTRFS_CSUM_TYPE_CRC32C=%d a_data=%p a_len=%d BTRFS_CSUM_RAWLEN=%d\n",a_csum_type,BTRFS_CSUM_TYPE_CRC32C,a_data,a_len,BTRFS_CSUM_RAWLEN);
#endif
    if (a_len < BTRFS_CSUM_RAWLEN){
#ifdef BTRFS_DEBUG
        btrfs_debug("a_data is too small\n");
#endif
        return false;
    }

    unsigned long v1=0, v2=0;
    switch (a_csum_type) {
    case BTRFS_CSUM_TYPE_CRC32C:
        // CRC-32C
        v1 = btrfs_csum_crc32c(a_data + BTRFS_CSUM_RAWLEN, a_len - BTRFS_CSUM_RAWLEN) ;
#ifdef BTRFS_DEBUG
        btrfs_debug("v1=%ld\n",v1);
#endif
        v2 = tsk_getu32(BTRFS_ENDIAN, a_data);
#ifdef BTRFS_DEBUG
        btrfs_debug("v2=%ld\n",v2);
#endif
        return v1 == v2;
    default:
#ifdef BTRFS_DEBUG
        btrfs_debug("default\n");
#endif
        return false;
    }
}



/*
 * superblock
 */


/**
 * Returns the physical address of a specific superblock mirror.
 * @param a_index mirror index in the range of 0 to (BTRFS_SUPERBLOCK_MIRRORS_MAX - 1)
 * @return physical superblock mirror address
 */
static TSK_DADDR_T
btrfs_superblock_address(const int a_index)
{
    return 1ULL << (a_index ? (14 + a_index * 12) : 16);
}


/**
 * Checks if a specific physical address is included by any superblock mirror.
 * @param a_btrfs Btrfs info
 * @param a_address physical address
 * @return true if the address is included, otherwise false
 */
static bool
btrfs_superblock_includes_address(const TSK_DADDR_T a_address)
{
    for (int i = 0; i < BTRFS_SUPERBLOCK_MIRRORS_MAX; i++) {
        TSK_DADDR_T sb_start = btrfs_superblock_address(i);
        if (a_address >= sb_start && a_address < sb_start + BTRFS_SUPERBLOCK_RAWLEN)
            return true;
    }
    return false;
}


/**
 * Tries to read the superblock at a specific physical address.
 * @param a_btrfs Btrfs info
 * @param a_offset physical address
 * @return pointer to the superblock if no error occured, otherwise NULL
 */
static BTRFS_SUPERBLOCK *
btrfs_superblock_read(BTRFS_INFO * a_btrfs, const TSK_DADDR_T a_offset)
{
    uint8_t raw[BTRFS_SUPERBLOCK_RAWLEN];

    btrfs_debug("trying to read superblock at offset 0x%" PRIxDADDR "\n", a_offset);

    // try to read raw superblock
    ssize_t result = tsk_fs_read(&a_btrfs->fs_info, a_offset, (char*) raw, sizeof(raw));
    if (result != (signed) sizeof(raw)) {
        tsk_error_reset();  // maybe the request was out of range, so reset error
        btrfs_debug("could not read superblock - tsk_fs_read result: %zd\n", result);
        if (tsk_verbose && !a_btrfs->test)
            tsk_fprintf(stderr, "btrfs_superblock_read: Could not read superblock - tsk_fs_read result: %zd\n", result);
        return NULL;
    }

    // check for magic
    if (memcmp(raw + BTRFS_SUPERBLOCK_MAGIC_OFFSET, BTRFS_SUPERBLOCK_MAGIC_VALUE, strlen(BTRFS_SUPERBLOCK_MAGIC_VALUE))) {
        btrfs_debug("superblock magic not found\n");
        if (tsk_verbose && !a_btrfs->test)
            tsk_fprintf(stderr, "btrfs_superblock_read: Superblock magic not found\n");
        return NULL;
    }

    BTRFS_SUPERBLOCK *sb = new BTRFS_SUPERBLOCK;
    btrfs_superblock_rawparse(raw, sb);

    // validate checksum
    if (!btrfs_csum_supported(sb->csum_type)) {
        btrfs_debug("superblock checksum type unknown - skipping\n");
        if (tsk_verbose && !a_btrfs->test)
            tsk_fprintf(stderr, "btrfs_superblock_read: Superblock checksum type unknown - skipping\n");
        delete sb;
        return NULL;
    }
    if (!btrfs_csum_valid(sb->csum_type, raw, sizeof(raw))) {
        btrfs_debug("superblock checksum invalid - skipping\n");
        if (tsk_verbose && !a_btrfs->test)
            tsk_fprintf(stderr, "btrfs_superblock_read: Superblock checksum invalid - skipping\n");
        delete sb;
        return NULL;
    }

    // ensure that the superblock belongs to the current filesystem
    if (sb->physical_address != a_offset) {
        btrfs_debug("superblock does not belong to the current filesystem\n");
        if (tsk_verbose && !a_btrfs->test)
            tsk_fprintf(stderr, "btrfs_superblock_read: Superblock does not belong to the current filesystem\n");
        delete sb;
        return NULL;
    }

    btrfs_debug("found valid superblock having generation: %" PRId64 "\n", sb->generation);
    if (tsk_verbose && !a_btrfs->test)
        tsk_fprintf(stderr, "btrfs_superblock_read: Found valid superblock having generation: %" PRId64 "\n", sb->generation);
    return sb;
}


/**
 * Searches for the valid superblock with the highest generation.
 * @param a_btrfs Btrfs info
 * @return true if a valid superblock was found, otherwise false
 */
static bool
btrfs_superblock_search(BTRFS_INFO * a_btrfs)
{
    a_btrfs->sb = NULL;
    for (int i = 0; i < BTRFS_SUPERBLOCK_MIRRORS_MAX; i++) {
        if (tsk_verbose && !a_btrfs->test)
            tsk_fprintf(stderr, "btrfs_superblock_search: Trying to read superblock mirror %d\n", i);

        BTRFS_SUPERBLOCK *tmp_sb = btrfs_superblock_read(a_btrfs, btrfs_superblock_address(i));

        // continue on invalid superblock mirror
        if (!tmp_sb)
            continue;

        // apply superblock (use highest generation)
        if (!a_btrfs->sb || a_btrfs->sb->generation < tmp_sb->generation) {
            delete a_btrfs->sb;
            a_btrfs->sb = tmp_sb;
            a_btrfs->sb_mirror_index = i;
        } else {
            delete tmp_sb;
        }
    }
    return a_btrfs->sb;
}



/*
 * chunks 1/2
 */


/**
 * Processes a chunk item and possibly adds it to a cached chunk mapping
 * @param a_btrfs Btrfs info
 * @param a_chunks pointer to cached chunk mapping
 * @param a_source_address source address belonging to the chunk item
 * @param a_ci_raw pointer to raw chunk item
 */
static void
btrfs_chunks_process_chunk_item(BTRFS_INFO * a_btrfs,
    BTRFS_CACHED_CHUNK_MAPPING * a_chunks, TSK_DADDR_T a_source_address,
    const uint8_t * a_ci_raw)
{
    // the chunks describe a 1:n log <-> phys relation, so we adopt only one stripe in log -> phys direction
    bool log2phys_added = false;

    BTRFS_CHUNK_ITEM *ci = btrfs_chunk_item_fromraw(a_ci_raw);

#ifdef BTRFS_DEBUG
    btrfs_debug("Processing chunk for logical address 0x%"  PRIx64 "...\n", a_source_address);
    btrfs_chunk_item_debugprint(ci);
#endif

    // check all stripes for affecting our device
    for (uint16_t i = 0; i < ci->number_of_stripes; i++) {
        BTRFS_CHUNK_ITEM_STRIPE *cis = &ci->stripes[i];
        if (cis->device_id != a_btrfs->sb->dev_item.device_id)
            continue;


        // convert info to internal format
        BTRFS_CACHED_CHUNK cc;
        cc.source_address = a_source_address;
        cc.size = ci->chunk_size;
        cc.target_address = cis->offset;

        // add to log -> phys mapping (only once)
        if (!log2phys_added) {
            a_chunks->log2phys.insert(a_chunks->log2phys.end(), cc);
            log2phys_added = true;
        }

        // add to phys -> log mapping
        cc.source_address = cis->offset;
        cc.target_address = a_source_address;
        a_chunks->phys2log.insert(cc);
    }
    btrfs_chunk_item_free(ci);
}


/**
 * Processes all chunks embedded into superblock into a newly created cached chunk mapping
 * @param a_btrfs Btrfs info
 * @return pointer to new cached chunk mapping
 */
static BTRFS_CACHED_CHUNK_MAPPING *
btrfs_chunks_from_superblock(BTRFS_INFO * a_btrfs)
{
    BTRFS_CACHED_CHUNK_MAPPING *chunks = new BTRFS_CACHED_CHUNK_MAPPING;
    BTRFS_KEY key;

    // iterate over all system chunks embedded into superblock
    btrfs_debug("Parsing superblock system chunks...\n");
    for (uint8_t *p = a_btrfs->sb->system_chunks; p < a_btrfs->sb->system_chunks + a_btrfs->sb->n;) {
        btrfs_key_rawparse(p, &key);
        p += BTRFS_KEY_RAWLEN;

        btrfs_chunks_process_chunk_item(a_btrfs, chunks, key.offset, p);
        p += btrfs_chunk_item_rawlen(p);
    }
    return chunks;
}


/**
 * Maps an address by using a cached chunk
 * @param a_cc pointer to a cached chunk
 * @param a_source_addr source address
 * @param a_target_addr pointer for target address
 * @return true if the source address could be mapped, otherwise false
 */
static bool
btrfs_chunk_map(const BTRFS_CACHED_CHUNK * a_cc,
    const TSK_DADDR_T a_source_addr, TSK_DADDR_T * a_target_addr)
{
#ifdef BTRFS_DEBUG
    btrfs_debug("btrfs_chunk_map [enter] a_cc=%x a_source_addr=%x a_target_addr=%x\n",a_cc,a_source_addr,a_target_addr);
#endif

    TSK_OFF_T offset = a_source_addr - a_cc->source_address;
    if (!(offset >= 0 && offset < a_cc->size))
        return false;

    *a_target_addr = a_cc->target_address + offset;
#ifdef BTRFS_DEBUG
    btrfs_debug("btrfs_chunk_map [exit] Mapping address 0x%" PRIxDADDR " to address 0x%" PRIxDADDR "\n", a_source_addr, *a_target_addr);
#endif
    return true;
}


/**
 * Returns the remaining bytes of a source address regarding a specific cached chunk (ignoring chunk range)
 * @param a_cc pointer to a cached chunk pointer (or NULL)
 * @param a_address source address
 * @return remaining bytes
 */
static inline TSK_OFF_T
btrfs_chunk_remaining_bytes(const BTRFS_CACHED_CHUNK * a_cc,
    const TSK_DADDR_T a_source_addr)
{
    return a_cc->source_address + a_cc->size - a_source_addr;
}


/**
 * Maps an address with regard to a specified mapping and gets a pointer to a cached chunk related to it, which is:
 *   a) a current chunk (including the address) => true  returned + *a_cc set + *a_target_addr set
 *   b) no current chunk, but the next chunk    => false returned + *a_cc set
 *   c) neither a current nor the next chunk    => false returned
 * @param a_mapping mapping out of cached chunks
 * @param a_cc pointer to a cached chunk pointer (or NULL)
 * @param a_source_addr source address
 * @param a_target_addr pointer for target address
 * @return true if the source address could be mapped, otherwise false
 */
static bool
btrfs_address_map(const btrfs_cached_chunks_t * a_mapping,
    const BTRFS_CACHED_CHUNK ** a_cc, const TSK_DADDR_T a_source_addr,
    TSK_DADDR_T * a_target_addr)
{
#ifdef BTRFS_DEBUG
    btrfs_debug("btrfs_address_map [enter] a_mapping=%x a_cc=%x a_source_addr=%x a_target_addr=%x\n",
                a_mapping,a_cc,a_source_addr,a_target_addr);
#endif

    // resolve to matching chunk, if possible
    BTRFS_CACHED_CHUNK cc;
    cc.source_address = a_source_addr;
    cc.size = 1;
    btrfs_cached_chunks_t::iterator result = a_mapping->lower_bound(cc);

    // if neither current nor next chunk, abort
    if (result == a_mapping->end())
        return false;

    const BTRFS_CACHED_CHUNK *result_cc = &(*result);
    if (a_cc)
        *a_cc = result_cc;

    // check for a) or b)
    return btrfs_chunk_map(result_cc, a_source_addr, a_target_addr);
}



/*
 * tree node stuff
 */


/**
 * Try to get a raw tree node from the treenode cache (lock must be taken!).
 * @param a_btrfs Btrfs info
 * @param a_address logical tree node address
 * @param a_data pointer to data buffer
 * @return true on cache hit, false otherwise
 */
static bool
btrfs_treenode_cache_get(BTRFS_INFO * a_btrfs, const TSK_DADDR_T a_address,
    uint8_t * a_data)
{
    btrfs_treenode_cache_map_t::iterator map_it = a_btrfs->treenode_cache_map->find(a_address);
    bool hit = map_it != a_btrfs->treenode_cache_map->end();
    if (hit) {
        memcpy(a_data, map_it->second, a_btrfs->sb->nodesize);

        // if not already at LRU list front, move to front
        if (a_btrfs->treenode_cache_lru->front() != a_address) {
            for (btrfs_treenode_cache_lru_t::iterator lru_it = a_btrfs->treenode_cache_lru->begin();
                    lru_it != a_btrfs->treenode_cache_lru->end(); lru_it++) {
                if (*lru_it == a_address) {
                    a_btrfs->treenode_cache_lru->erase(lru_it);
                    break;
                }
            }
            a_btrfs->treenode_cache_lru->push_front(a_address);
        }
    }

    btrfs_debug("cache %s at address 0x%" PRIxDADDR " (entry count: %zu)\n", hit ? "hit" : "miss", a_address, a_btrfs->treenode_cache_lru->size());
    return hit;
}


/**
 * Puts a raw tree node into the treenode cache (lock must be taken; node must not yet be in cache!).
 * @param a_btrfs Btrfs info
 * @param a_address logical tree node address
 * @param a_data pointer to data buffer
 */
static void
btrfs_treenode_cache_put(BTRFS_INFO * a_btrfs, const TSK_DADDR_T a_address,
    const uint8_t * a_data)
{
#ifdef BTRFS_DEBUG
    btrfs_debug("btrfs_treenode_cache_put a_btrfs=%x data=%x\n",a_btrfs,a_data);
#endif
    uint8_t *target_data;
    size_t cache_size = a_btrfs->treenode_cache_lru->size();
    if (cache_size < BTRFS_TREENODE_CACHE_SIZE) {
        // add new entry
        target_data = new uint8_t[a_btrfs->sb->nodesize];
        btrfs_debug("caching address 0x%" PRIxDADDR " (entry count: %zu; entry was new)\n", a_address, cache_size + 1);
    } else {
        // replace old entry
        TSK_DADDR_T old_address = a_btrfs->treenode_cache_lru->back();
        a_btrfs->treenode_cache_lru->pop_back();

        btrfs_treenode_cache_map_t::iterator map_it = a_btrfs->treenode_cache_map->find(old_address);
        target_data = map_it->second;
        a_btrfs->treenode_cache_map->erase(map_it);

        btrfs_debug("caching address 0x%" PRIxDADDR " (entry count: %zu; entry replaced address 0x%" PRIxDADDR ")\n", a_address, cache_size, old_address);
    }

#ifdef BTRFS_DEBUG
    btrfs_debug("starting memcpy...\n");
#endif
    memcpy(target_data, a_data, a_btrfs->sb->nodesize);
#ifdef BTRFS_DEBUG
    btrfs_debug("done...\n");
#endif
    a_btrfs->treenode_cache_map->insert(btrfs_treenode_cache_map_t::value_type(a_address, target_data));
    a_btrfs->treenode_cache_lru->push_front(a_address);
}


/**
 * Goes one tree level up by removing the bottom node
 * @param a_node pointer to treenode structure pointer
 */
static void
btrfs_treenode_pop(BTRFS_TREENODE ** a_node)
{
    BTRFS_TREENODE *node = *a_node;
    *a_node = node->prev;

    delete[] node->data;
    delete node;
}


/**
 * Frees a complete treenode structure
 * @param a_node pointer to treenode structure
 */
static void
btrfs_treenode_free(BTRFS_TREENODE * a_node)
{
#ifdef BTRFS_DEBUG
    btrfs_debug("btrfs_treenode_free...\n");
#endif
    while (a_node)
        btrfs_treenode_pop(&a_node);
}


/**
 * Compares two BTRFS_KEYs.
 * @param a_key_a key A
 * @param a_key_b key B
 * @param a_flags flags
 * @return relation between key A and key B
 */
static int
btrfs_cmp(const BTRFS_KEY * a_key_a, const BTRFS_KEY * a_key_b,
    const int a_flags)
{
    // compare key fields one after each other

    if (!(a_flags & BTRFS_CMP_IGNORE_OBJID)) {
        if (a_key_a->object_id > a_key_b->object_id)
            return 1;
        if (a_key_a->object_id < a_key_b->object_id)
            return -1;
    }

    if (!(a_flags & BTRFS_CMP_IGNORE_TYPE)) {
        // special flag to cover two types which only differ in LSB
        int shift = a_flags & BTRFS_CMP_IGNORE_LSB_TYPE ? 1 : 0;

        if ((a_key_a->item_type >> shift) > (a_key_b->item_type >> shift))
            return 1;
        if ((a_key_a->item_type >> shift) < (a_key_b->item_type >> shift))
            return -1;
    }

    if (!(a_flags & BTRFS_CMP_IGNORE_OFFSET)) {
        if (a_key_a->offset > a_key_b->offset)
            return 1;
        if (a_key_a->offset < a_key_b->offset)
            return -1;
    }

    return 0;
}


/**
 * Selects the current item of a node (the resulting index must be valid!)
 * @param a_node pointer to treenode structure
 * @param a_absolute TRUE, if an absolute index is specified, otherwise it is treatened as relative index
 * @param a_index index
 */
static void
btrfs_treenode_set_index(BTRFS_TREENODE * a_node, const bool a_absolute,
    const int a_index)
{
    a_node->index = (a_absolute ? 0 : a_node->index) + a_index;

    // update values
    uint8_t *raw = a_node->data + a_node->index *
            (a_node->header.level ? BTRFS_KEY_POINTER_RAWLEN : BTRFS_ITEM_RAWLEN);
    btrfs_key_rawparse(raw, &a_node->key);
    raw += BTRFS_KEY_RAWLEN;

    if (a_node->header.level)
        btrfs_key_pointer_rest_rawparse(raw, &a_node->kp);
    else
        btrfs_item_rest_rawparse(raw, &a_node->item);
}


/**
 * Returns a pointer to the raw item data of the current index of the current node
 * @param a_node pointer to treenode structure
 * @return pointer to raw data
 */
static inline uint8_t *
btrfs_treenode_itemdata(const BTRFS_TREENODE * a_node)
{
    return a_node->data + a_node->item.data_offset;
}


/**
 * Returns the size of the raw item data of the current index of the current node
 * @param a_node pointer to treenode structure
 * @return raw data size
 */
static inline uint32_t
btrfs_treenode_itemsize(const BTRFS_TREENODE * a_node)
{
    return a_node->item.data_size;
}


/**
 * Goes one tree level down by adding a new node
 * @param a_btrfs Btrfs info
 * @param a_node pointer to treenode structure pointer (treenode structure pointer itself may be NULL)
 * @param a_address logical node address
 * @param a_initial_index initial index to be set
 * @return true if no error occured, false otherwise
 */
static bool
btrfs_treenode_push(BTRFS_INFO * a_btrfs, BTRFS_TREENODE ** a_node,
    const TSK_DADDR_T a_address, const BTRFS_DIRECTION a_initial_index)
{
#ifdef BTRFS_DEBUG
    btrfs_debug(" btrfs_treenode_push a_btrfs=%x\n",a_btrfs);
    btrfs_debug(" btrfs_treenode_push a_btrfs->sb=%x\n",a_btrfs->sb);
    btrfs_debug(" btrfs_treenode_push a_btrfs->sb->nodesize=%d\n",a_btrfs->sb->nodesize);
#endif
    const size_t nodesize = a_btrfs->sb->nodesize;
    if (nodesize<=0) return false;
    //uint8_t raw[nodesize];
    uint8_t *raw = new uint8_t[nodesize];

    // lock remains taken between cache get and a possible put in order to prevent an possible meanwhile cache put by another thread
    tsk_take_lock(&a_btrfs->treenode_cache_lock);

    // on treenode cache miss fetch node from image
    if (!btrfs_treenode_cache_get(a_btrfs, a_address, raw)) {
        // map address
#ifdef BTRFS_DEBUG
        btrfs_debug("in loop. raw=%x\n",raw);
#endif

        TSK_DADDR_T phys_address;
        if (!btrfs_address_map(&a_btrfs->chunks->log2phys, NULL, a_address, &phys_address)) {
            btrfs_error(TSK_ERR_FS_BLK_NUM,"btrfs_treenode_push: Could not map logical address: 0x%" PRIxDADDR, a_address);
            tsk_release_lock(&a_btrfs->treenode_cache_lock);
#ifdef BTRFS_DEBUG
            btrfs_debug("return point 1\n");
#endif
            delete[] raw;
            return false;
        }

#ifdef BTRFS_DEBUG
        btrfs_debug("progress point 1\n");
#endif

        // get node data
        ssize_t result = tsk_fs_read(&a_btrfs->fs_info, phys_address, (char*) raw, nodesize);
        if (result != (signed) nodesize) {
            if (result >= 0)
                btrfs_error(TSK_ERR_FS_READ, "btrfs_treenode_push: Error reading treenode at physical address: 0x%" PRIxDADDR, phys_address);
            else
                tsk_error_set_errstr2("btrfs_treenode_push: Error reading treenode at physical address: 0x%" PRIxDADDR, phys_address);
            tsk_release_lock(&a_btrfs->treenode_cache_lock);
#ifdef BTRFS_DEBUG
            btrfs_debug("return point 2\n");
#endif
            delete[] raw;
            return false;
        }

#ifdef BTRFS_DEBUG
        btrfs_debug("progress point 2\n");
#endif
#ifdef BTRFS_CHECK_TREENODE_CSUM
        // validate checksum
        if (!btrfs_csum_valid(a_btrfs->sb->csum_type, raw, nodesize)) {
            btrfs_error(TSK_ERR_FS_INODE_COR,
                    "btrfs_treenode_push: treenode checksum invalid at logical / physical address: 0x%" PRIxDADDR " / 0x%" PRIxDADDR, a_address, phys_address);
            tsk_release_lock(&a_btrfs->treenode_cache_lock);
#ifdef BTRFS_DEBUG
            btrfs_debug("return point 3\n");
#endif
            delete[] raw;
            return false;
        }
        btrfs_debug("treenode checksum valid\n");
#endif
#ifdef BTRFS_DEBUG
        btrfs_debug("progress point 3\n");
#endif
        btrfs_treenode_cache_put(a_btrfs, a_address, raw);
    }
#ifdef BTRFS_DEBUG
    btrfs_debug("loop done\n");
#endif
    tsk_release_lock(&a_btrfs->treenode_cache_lock);
    // append node
    btrfs_debug("treenode push at address 0x%" PRIxDADDR " (logical)\n", a_address);
    BTRFS_TREENODE *node = new BTRFS_TREENODE;
    node->prev = *a_node;

    btrfs_tree_header_rawparse(raw, &node->header);

    // validate header address
    if (node->header.logical_address != a_address) {
        btrfs_error(TSK_ERR_FS_INODE_COR,
                "btrfs_treenode_push: logical address different to header: 0x%" PRIxDADDR " / 0x%" PRIxDADDR, a_address, node->header.logical_address);
        btrfs_treenode_pop(&node);  // NOT btrfs_treenode_free - otherwise the upper levels would also be freed!
        delete[] raw;
        return false;
    }

    size_t data_size = nodesize - BTRFS_TREE_HEADER_RAWLEN;
    node->data = new uint8_t[data_size];
    memcpy(node->data, raw + BTRFS_TREE_HEADER_RAWLEN, data_size);

    btrfs_treenode_set_index(node, true, a_initial_index == BTRFS_FIRST ? 0 : node->header.number_of_items - 1);

    *a_node = node;
    delete[] raw;
    return true;
}


/**
 * Returns the first/last item of a tree
 * @param a_btrfs Btrfs info
 * @param a_address logical root node address
 * @param a_direction extremum to be returned
 * @return requested tree item, or NULL on error
 */
static BTRFS_TREENODE *
btrfs_treenode_extremum(BTRFS_INFO * a_btrfs, TSK_DADDR_T a_address,
    const BTRFS_DIRECTION a_direction)
{
    BTRFS_TREENODE *node = NULL;
    for (;;) {
#ifdef BTRFS_DEBUG
        btrfs_debug(" btrfs_treenode_extremum node==%x\n",node);
#endif
        if (!btrfs_treenode_push(a_btrfs, &node, a_address, a_direction)) {
            btrfs_treenode_free(node);
            return NULL;
        }
        btrfs_debug("btrfs_treenode_extremum looking for %s at level %d (address: 0x%" PRIxDADDR ")\n",
                a_direction == BTRFS_LAST ? "maximum" : "minimum", node->header.level, a_address);

        if (!node->header.level)
            break;

        // go downwards
        a_address = node->kp.block_number;
    }
    return node;
}


/**
 * Searches a tree for a specific leaf node. If more than one leaf node matches the considered key parts, the one with the HIGHEST key is chosen.
 * @param a_btrfs Btrfs info
 * @param a_node pointer to treenode structure pointer
 * @param a_address logical root node address
 * @param a_key key
 * @param a_cmp_flags cmp flags
 * @param a_flags flags
 * @return result
 */
static BTRFS_TREENODE_RESULT
btrfs_treenode_search(BTRFS_INFO * a_btrfs, BTRFS_TREENODE ** a_node,
    TSK_DADDR_T a_address, const BTRFS_KEY * a_key, const int a_cmp_flags,
    const int a_flags)
{
#ifdef BTRFS_DEBUG
    btrfs_debug("### search key ###\n");
    btrfs_key_debugprint(a_key);
#endif

    BTRFS_TREENODE *node = NULL;
    for (;;) {
        if (!btrfs_treenode_push(a_btrfs, &node, a_address, BTRFS_FIRST)) {
            btrfs_treenode_free(node);
            return BTRFS_TREENODE_ERROR;
        }

        uint32_t index_min = 0;
        uint32_t index_max = node->header.number_of_items - 1;
        while (index_min != index_max) {
            btrfs_treenode_set_index(node, true, index_max - (index_max - index_min) / 2);  // rounding up - needed for correct selection of inside nodes!
#ifdef BTRFS_DEBUG
//          btrfs_debug("min = %d, max = %d, node->index = %d\n", index_min, index_max, node->index);
            btrfs_debug("### level %d node - key (loop  cmp @ index %" PRId32 " of %" PRId32 ") ###\n",
                    node->header.level, node->index, node->header.number_of_items);
            btrfs_key_debugprint(&node->key);
#endif

            if (btrfs_cmp(a_key, &node->key, a_cmp_flags) < 0)
                index_max = node->index - 1;
            else
                index_min = node->index;
        }
        btrfs_treenode_set_index(node, true, index_min);

#ifdef BTRFS_DEBUG
        btrfs_debug("### level %d node - key (final cmp @ index %" PRId32 " of %" PRId32 ") ###\n",
                node->header.level, node->index, node->header.number_of_items);
        btrfs_key_debugprint(&node->key);
#endif

        int cmp = btrfs_cmp(a_key, &node->key, a_cmp_flags);
        if (node->header.level) {
            // ***** INSIDE NODE *****
            if (cmp >= 0) {
                a_address = node->kp.block_number;
                continue;
            }
        } else {
            // *****     LEAF    *****
            if (cmp == 0 || (a_flags & BTRFS_SEARCH_ALLOW_LEFT_NEIGHBOUR)) {
                *a_node = node;
                return BTRFS_TREENODE_FOUND;
            }
        }
        break;
    }

    // node not found
    btrfs_treenode_free(node);
    return BTRFS_TREENODE_NOT_FOUND;
}


/**
 * Goes a single step within a tree
 * @param a_btrfs Btrfs info
 * @param a_node pointer to treenode structure pointer
 * @param a_direction direction to go
 * @return result
 */
static BTRFS_TREENODE_RESULT
btrfs_treenode_single_step(BTRFS_INFO * a_btrfs, BTRFS_TREENODE ** a_node,
    const BTRFS_DIRECTION a_direction)
{
    BTRFS_TREENODE *node = *a_node;

    // check if first/last tree node + count necessary pops
    int pop_count = 0;
    while (node->index == (a_direction == BTRFS_LAST ? node->header.number_of_items - 1 : 0)) {
        node = node->prev;
        if (!node)
            return BTRFS_TREENODE_NOT_FOUND;    // abort due to first/last item
        pop_count++;
    }

    // do the step
    btrfs_treenode_set_index(node, false, a_direction == BTRFS_LAST ? 1 : -1);

    // while not yet at leaf level, do a push
    for (int push_count = 0; node->header.level; push_count++) {
        if (!btrfs_treenode_push(a_btrfs, &node, node->kp.block_number,
                a_direction == BTRFS_LAST ? BTRFS_FIRST : BTRFS_LAST)) {

            // undo pushes and step (the old leaf sub-path is still intact, so leave *a_node unaltered)
            while (push_count--)
                btrfs_treenode_pop(&node);
            btrfs_treenode_set_index(node, false, a_direction == BTRFS_LAST ? -1 : 1);

            return BTRFS_TREENODE_ERROR;
        }
    }

    // do the pops (on the old leaf sub-path)
    while (pop_count--)
        btrfs_treenode_pop(a_node);

    *a_node = node;
    return BTRFS_TREENODE_FOUND;
}


/**
 * Goes steps within a tree
 * @param a_btrfs Btrfs info
 * @param a_node pointer to treenode structure pointer
 * @param a_key key
 * @param a_cmp_flags cmp flags
 * @param a_direction direction to go
 * @param a_flags flags
 * @return result
 */
static BTRFS_TREENODE_RESULT
btrfs_treenode_step(BTRFS_INFO * a_btrfs, BTRFS_TREENODE ** a_node,
    const BTRFS_KEY * a_key, const int a_cmp_flags,
    const BTRFS_DIRECTION a_direction, const int a_flags)
{
    // if requested, try to do an initial step to ensure that not the original item is returned
    if (a_flags & BTRFS_STEP_INITIAL) {
        BTRFS_TREENODE_RESULT result = btrfs_treenode_single_step(a_btrfs, a_node, a_direction);
        if (result != BTRFS_TREENODE_FOUND)
            return result;
    }

    // while key mismatch
    while (btrfs_cmp((const BTRFS_KEY*) &(*a_node)->key, a_key, a_cmp_flags)) {
        // if multiple steps not wanted, return
        if (!(a_flags & BTRFS_STEP_REPEAT))
            return BTRFS_TREENODE_NOT_FOUND;

        // try to do single step
        BTRFS_TREENODE_RESULT result = btrfs_treenode_single_step(a_btrfs, a_node, a_direction);
        if (result != BTRFS_TREENODE_FOUND)
            return result;
    }
    return BTRFS_TREENODE_FOUND;
}


/**
 * Searches a tree for a specific leaf node. If more than one leaf node matches the considered key parts, the one with the LOWEST key is chosen.
 * @param a_btrfs Btrfs info
 * @param a_node pointer to treenode structure pointer
 * @param a_address logical root node address
 * @param a_key key (all ignored key parts must be zeroed!)
 * @param a_cmp_flags cmp flags
 * @return result
 */
static BTRFS_TREENODE_RESULT
btrfs_treenode_search_lowest(BTRFS_INFO * a_btrfs,
    BTRFS_TREENODE ** a_node, TSK_DADDR_T a_address,
    const BTRFS_KEY * a_key, const int a_cmp_flags)
{
    BTRFS_TREENODE *node = NULL;

    // get either the desired node itself or its left neighbour
    BTRFS_TREENODE_RESULT node_result = btrfs_treenode_search(a_btrfs, &node, a_address, a_key,
            0, BTRFS_SEARCH_ALLOW_LEFT_NEIGHBOUR);
    if (node_result == BTRFS_TREENODE_ERROR)
        return BTRFS_TREENODE_ERROR;
    if (node_result == BTRFS_TREENODE_NOT_FOUND) {
        // neither exists, so it only could be the first tree node
        node = btrfs_treenode_extremum(a_btrfs, a_address, BTRFS_FIRST);
        if (!node)
            return BTRFS_TREENODE_ERROR;

        if (!btrfs_cmp(a_key, &node->key, a_cmp_flags)) {
            *a_node = node;
            return BTRFS_TREENODE_FOUND;
        }
        btrfs_treenode_free(node);
        return BTRFS_TREENODE_NOT_FOUND;
    }

    // check if desired node
    if (!btrfs_cmp(a_key, &node->key, a_cmp_flags)) {
        *a_node = node;
        return BTRFS_TREENODE_FOUND;
    }

    // left neighbour, so it only could be the next node
    node_result = btrfs_treenode_step(a_btrfs, &node, a_key,
            a_cmp_flags, BTRFS_LAST, BTRFS_STEP_INITIAL);
    if (node_result == BTRFS_TREENODE_FOUND) {
        *a_node = node;
        return BTRFS_TREENODE_FOUND;
    }
    btrfs_treenode_free(node);
    return node_result;
}


/**
 * Derives the logical root node address of a specific subtree from the root tree
 * @param a_btrfs Btrfs info
 * @param a_obj_id object ID of the subtree
 * @param a_node_tree_address pointer to the logical root node address
 * @return true if no error occured, false otherwise
 */
static bool
btrfs_root_tree_derive_subtree_address(BTRFS_INFO * a_btrfs,
    uint64_t a_obj_id, uint64_t * a_node_tree_address)
{
    BTRFS_KEY key;
    key.object_id = a_obj_id;
    key.item_type = BTRFS_ITEM_TYPE_ROOT_ITEM;
    key.offset = 0; // not used, except at debug output

    BTRFS_TREENODE *node = NULL;
    BTRFS_TREENODE_RESULT node_result = btrfs_treenode_search(a_btrfs, &node, a_btrfs->sb->root_tree_root, &key,
            BTRFS_CMP_IGNORE_OFFSET, 0);
    if (node_result == BTRFS_TREENODE_ERROR)
        return false;
    if (node_result == BTRFS_TREENODE_NOT_FOUND) {
        btrfs_error(TSK_ERR_FS_CORRUPT,
                "btrfs_root_tree_derive_node_tree_address: Could not find ROOT_ITEM of object ID 0x%" PRIu64 " in root tree", a_obj_id);
        return false;
    }

    BTRFS_ROOT_ITEM root_item;
    btrfs_root_item_rawparse(btrfs_treenode_itemdata(node), &root_item);

#ifdef BTRFS_DEBUG
    btrfs_debug("#####\n");
    btrfs_debug("ROOT_ITEM of object ID 0x%" PRIu64 ":\n", a_obj_id);
    btrfs_root_item_debugprint(&root_item);
#endif

    *a_node_tree_address = root_item.root_node_block_number;

    btrfs_treenode_free(node);
    return true;
}



/*
 * chunks 2/2
 */


/**
 * Processes all chunks of the chunk tree into a newly created cached chunk mapping
 * @param a_btrfs Btrfs info
 * @return pointer to new cached chunk mapping if no error occurs, otherwise NULL
 */
static BTRFS_CACHED_CHUNK_MAPPING *
btrfs_chunks_from_chunktree(BTRFS_INFO * a_btrfs)
{
    // superblock system chunks must already have been derived!

    BTRFS_KEY key;
    key.object_id = BTRFS_OBJID_CHUNK_ITEM;
    key.item_type = BTRFS_ITEM_TYPE_CHUNK_ITEM;
    key.offset = 0; // not used, except at debug output

    // iterate through chunk tree
#ifdef BTRFS_DEBUG
    btrfs_debug("Parsing chunk tree chunks...\n");
#endif
    BTRFS_TREENODE *node = btrfs_treenode_extremum(a_btrfs, a_btrfs->sb->chunk_tree_root, BTRFS_FIRST);
#ifdef BTRFS_DEBUG
    btrfs_debug(" node==%x\n",node);
#endif
    if (!node) {
        return NULL;
    }

    // first CHUNK_ITEM
    BTRFS_TREENODE_RESULT node_result = btrfs_treenode_step(a_btrfs, &node, &key,
            BTRFS_CMP_IGNORE_OFFSET, BTRFS_LAST, BTRFS_STEP_REPEAT);
    if (node_result != BTRFS_TREENODE_FOUND) {
        if (node_result == BTRFS_TREENODE_NOT_FOUND)
            btrfs_error(TSK_ERR_FS_CORRUPT,
                    "btrfs_chunks_from_chunktree: Could not find any CHUNK_ITEM in chunk tree");
        btrfs_treenode_free(node);
        return NULL;
    }

#ifdef BTRFS_DEBUG
    btrfs_debug("Parsing chunk mapping...\n");
#endif
    BTRFS_CACHED_CHUNK_MAPPING *chunks = new BTRFS_CACHED_CHUNK_MAPPING;
    do {
        btrfs_chunks_process_chunk_item(a_btrfs, chunks, node->key.offset, btrfs_treenode_itemdata(node));

        // next CHUNK_ITEM
        node_result = btrfs_treenode_step(a_btrfs, &node, &key,
                BTRFS_CMP_IGNORE_OFFSET, BTRFS_LAST, BTRFS_STEP_INITIAL | BTRFS_STEP_REPEAT);
        if (node_result == BTRFS_TREENODE_ERROR) {
            btrfs_treenode_free(node);
            delete chunks;
            return NULL;
        }
    } while (node_result == BTRFS_TREENODE_FOUND);

    btrfs_treenode_free(node);
    return chunks;
}



/*
 * subvolumes
 */


/**
 * Add the subvolume described by the specified ROOT_ITEM
 * @param a_btrfs Btrfs info
 * @param a_node pointer to treenode structure with a selected ROOT_ITEM
 * @return true if no error occured, false otherwise
 */
static bool
btrfs_parse_subvolume(BTRFS_INFO * a_btrfs, BTRFS_TREENODE * a_node)
{
    // create subvolume
    uint64_t subvol_id = a_node->key.object_id;
    BTRFS_SUBVOLUME *subvol = &((*a_btrfs->subvolumes)[subvol_id]);
    btrfs_root_item_rawparse(btrfs_treenode_itemdata(a_node), &subvol->ri);

    BTRFS_KEY key;
    key.object_id = 0;  // not used, except at debug output
    key.item_type = BTRFS_ITEM_TYPE_INODE_ITEM;
    key.offset = 0;

    // iterate over all inodes
    BTRFS_TREENODE *node = btrfs_treenode_extremum(a_btrfs, subvol->ri.root_node_block_number, BTRFS_FIRST);
    if (!node)
        return false;

    // first INODE_ITEM
    BTRFS_TREENODE_RESULT node_result = btrfs_treenode_step(a_btrfs, &node, &key,
            BTRFS_CMP_IGNORE_OBJID, BTRFS_LAST, BTRFS_STEP_REPEAT);
    if (node_result != BTRFS_TREENODE_FOUND) {
        if (node_result == BTRFS_TREENODE_NOT_FOUND)
            btrfs_error(TSK_ERR_FS_CORRUPT,
                    "btrfs_parse_subvolume: Could not find any INODE_ITEM in subvolume tree 0x%" PRIx64, subvol_id);
        btrfs_treenode_free(node);
        return false;
    }

    do {
        // add to virt->real mapping
        TSK_INUM_T inum = node->key.object_id;
        a_btrfs->virt2real_inums->push_back(btrfs_virt2real_inums_t::value_type(subvol_id, inum));

        // add to real->virt mapping
        TSK_INUM_T vinum = a_btrfs->virt2real_inums->size() - 1;
        subvol->real2virt_inums.insert(subvol->real2virt_inums.end(),
                btrfs_real2virt_inums_t::value_type(inum, vinum));

        // next INODE_ITEM
        node_result = btrfs_treenode_step(a_btrfs, &node, &key,
                BTRFS_CMP_IGNORE_OBJID, BTRFS_LAST, BTRFS_STEP_INITIAL | BTRFS_STEP_REPEAT);
        if (node_result == BTRFS_TREENODE_ERROR) {
            btrfs_treenode_free(node);
            return false;
        }
    } while (node_result == BTRFS_TREENODE_FOUND);

    btrfs_treenode_free(node);
    btrfs_debug("########## subvolume 0x%" PRIx64 " with %zd inodes ##########\n",
            subvol_id, subvol->real2virt_inums.size());
    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_parse_subvolume: inodes in subvolume 0x%" PRIx64 "%s: %zd\n",
                subvol_id, subvol_id == BTRFS_OBJID_FS_TREE ? " (FS_TREE)" : "", subvol->real2virt_inums.size());
    return true;
}


/**
 * Add all subvolumes
 * @param a_btrfs Btrfs info
 * @return true if no error occured, false otherwise
 */
static bool
btrfs_parse_subvolumes(BTRFS_INFO * a_btrfs)
{
    BTRFS_KEY key;
    key.object_id = BTRFS_OBJID_FS_TREE;
    key.item_type = BTRFS_ITEM_TYPE_ROOT_ITEM;
    key.offset = 0; // not used, except at debug output

    // iterate through all tree roots
    BTRFS_TREENODE *node = NULL;
    BTRFS_TREENODE_RESULT node_result = btrfs_treenode_search(a_btrfs, &node, a_btrfs->sb->root_tree_root, &key,
            BTRFS_CMP_IGNORE_OFFSET, 0);
    if (node_result == BTRFS_TREENODE_ERROR)
        return false;
    if (node_result == BTRFS_TREENODE_NOT_FOUND) {
        btrfs_error(TSK_ERR_FS_CORRUPT,
                "btrfs_parse_subvolumes: Could not find FS_TREE in root tree");
        return false;
    }

    do {
        // only process FS_TREE and subvolumes
        uint64_t subvol = node->key.object_id;
        if (subvol == BTRFS_OBJID_FS_TREE || (subvol >= BTRFS_OBJID_MIN && subvol <= BTRFS_OBJID_MAX)) {
            if (!btrfs_parse_subvolume(a_btrfs, node)) {
                btrfs_treenode_free(node);
                return false;
            }
        }

        // next ROOT_ITEM
        node_result = btrfs_treenode_step(a_btrfs, &node, &key,
                BTRFS_CMP_IGNORE_OBJID | BTRFS_CMP_IGNORE_OFFSET, BTRFS_LAST, BTRFS_STEP_INITIAL | BTRFS_STEP_REPEAT);
        if (node_result == BTRFS_TREENODE_ERROR) {
            btrfs_treenode_free(node);
            return false;
        }
    } while (node_result == BTRFS_TREENODE_FOUND);

    btrfs_treenode_free(node);
    return true;
}


/**
 * Maps a virtual inum to a real inum
 * @param a_btrfs Btrfs info
 * @param a_vinum virtual inum
 * @param a_subvol pointer to subvolume ID
 * @param a_inum pointer to real inum
 * @return true if no error occured, false otherwise
 */
static bool
btrfs_inum_virt2real_map(BTRFS_INFO * a_btrfs, const TSK_INUM_T a_vinum,
    uint64_t * a_subvol, TSK_INUM_T * a_inum)
{
    // ignore exceeded range (and thereby special virtual inums)
    if (a_vinum >= a_btrfs->virt2real_inums->size()) {
        btrfs_error(TSK_ERR_FS_ARG,
                "btrfs_inum_virt2real_map: invalid virtual inum: %" PRIuINUM, a_vinum);
        return false;
    }

    btrfs_virt2real_inums_t::value_type result = (*a_btrfs->virt2real_inums)[a_vinum];

    *a_subvol = result.first;
    *a_inum = result.second;
    return true;
}


/**
 * Maps a real inum to a virtual inum
 * @param a_btrfs Btrfs info
 * @param a_subvol subvolume ID
 * @param a_inum real inum
 * @param a_vinum pointer to virtual inum
 * @return true if no error occured, false otherwise
 */
static bool
btrfs_inum_real2virt_map(BTRFS_INFO * a_btrfs, const uint64_t a_subvol,
    const TSK_INUM_T a_inum, TSK_INUM_T * a_vinum)
{
    btrfs_subvolumes_t::iterator subvol_it = a_btrfs->subvolumes->find(a_subvol);
    if (subvol_it == a_btrfs->subvolumes->end()) {
        btrfs_error(TSK_ERR_FS_ARG,
                "btrfs_inum_real2virt_map: invalid subvolume ID: 0x%" PRIx64, a_subvol);
        return false;
    }

    btrfs_real2virt_inums_t::iterator inode_it = subvol_it->second.real2virt_inums.find(a_inum);
    if (inode_it == subvol_it->second.real2virt_inums.end()) {
        btrfs_error(TSK_ERR_FS_ARG,
                "btrfs_inum_real2virt_map: invalid real inum: %" PRIuINUM, a_inum);
        return false;
    }

    *a_vinum = inode_it->second;
    return true;
}


/**
 * Derives the set default subvolume.
 * @param a_btrfs Btrfs info
 * @return subvolume ID if no error occured, otherwise 0
 */
static uint64_t
btrfs_subvol_default(BTRFS_INFO * a_btrfs)
{
    BTRFS_KEY key;
    key.object_id = a_btrfs->sb->root_dir_objectid;
    key.item_type = BTRFS_ITEM_TYPE_DIR_ITEM;
    key.offset = 0; // not used, except at debug output

    BTRFS_TREENODE *node = NULL;
    BTRFS_TREENODE_RESULT node_result = btrfs_treenode_search(a_btrfs, &node, a_btrfs->sb->root_tree_root, &key,
            BTRFS_CMP_IGNORE_OFFSET, 0);
    if (node_result == BTRFS_TREENODE_ERROR)
        return 0;
    if (node_result == BTRFS_TREENODE_NOT_FOUND) {
        // default to FS_TREE
        return BTRFS_OBJID_FS_TREE;
    }

    // ensure this is the only entry
    BTRFS_DIR_ENTRY *de = btrfs_dir_entry_fromraw(btrfs_treenode_itemdata(node), btrfs_treenode_itemsize(node));
    if (de->next) {
        btrfs_error(TSK_ERR_FS_CORRUPT,
                "btrfs_subvol_default: DIR_ITEM item with more than one entry");
        btrfs_treenode_free(node);
        btrfs_dir_entry_free(de);
        return 0;
    }
#ifdef BTRFS_DEBUG
    btrfs_debug("### DIR_ITEM ###\n");
    btrfs_dir_entry_debugprint(de);
#endif

    // ensure expected name
    if (strcmp(de->name, "default")) {
        btrfs_error(TSK_ERR_FS_CORRUPT,
                "btrfs_subvol_default: DIR_ITEM has wrong name: %s", de->name);
        btrfs_treenode_free(node);
        btrfs_dir_entry_free(de);
        return 0;
    }

    // success
    uint64_t subvol = de->child.object_id;
    btrfs_treenode_free(node);
    btrfs_dir_entry_free(de);
    return subvol;
}


/**
 * Returns the logical root node address of a subvolume (which must exist)
 * @param a_btrfs Btrfs info
 * @param a_subvol subvolume ID
 * @return tree address
 */
static TSK_DADDR_T
btrfs_subvol_tree_address(BTRFS_INFO * a_btrfs, const uint64_t a_subvol)
{
    return (*a_btrfs->subvolumes)[a_subvol].ri.root_node_block_number;
}


/**
 * Returns the real root inum of a subvolume (which must exist)
 * @param a_btrfs Btrfs info
 * @param a_subvol subvolume ID
 * @return root inum
 */
static TSK_INUM_T
btrfs_subvol_root_inum(BTRFS_INFO * a_btrfs, const uint64_t a_subvol)
{
    return (*a_btrfs->subvolumes)[a_subvol].ri.root_dir_object_id;
}



/*
 * block walk
 */


/**
 * Allocates a blockwalk structure
 * @param a_btrfs Btrfs info
 * @param a_start_block physical block to start the blockwalk with
 * @return pointer to blockwalk structure
 */
static BTRFS_BLOCKWALK *
btrfs_blockwalk_alloc(BTRFS_INFO * a_btrfs, const uint64_t a_start_block)
{
    BTRFS_BLOCKWALK *bw = new BTRFS_BLOCKWALK;
    bw->btrfs = a_btrfs;
    bw->block = a_start_block;

    bw->no_more_ei = false;
    bw->ei_key.item_type = BTRFS_ITEM_TYPE_EXTENT_ITEM & BTRFS_ITEM_TYPE_METADATA_ITEM; // via BTRFS_CMP_IGNORE_LSB_TYPE this includes both types!
    bw->ei_key.offset = 0;  // not used, except at debug output
    bw->ei_node = NULL;
    bw->ei_start = 0;
    bw->ei_end = 0;

    bw->no_more_cc = false;
    bw->cc = NULL;
    return bw;
}


/**
 * Frees a blockwalk structure
 * @param a_bw pointer to blockwalk structure
 */
static void
btrfs_blockwalk_free(BTRFS_BLOCKWALK * a_bw)
{
    if (!a_bw)
        return;

    if (a_bw->ei_node)
        btrfs_treenode_free(a_bw->ei_node);
    delete a_bw;
}


/**
 * Applies the values of the current selected extent item to the blockwalk structure
 * @param a_bw pointer to blockwalk structure
 */
static void
btrfs_blockwalk_apply_extent_item(BTRFS_BLOCKWALK * a_bw)
{
    BTRFS_EXTENT_ITEM ei;
    btrfs_extent_item_rawparse(btrfs_treenode_itemdata(a_bw->ei_node), &ei);

    a_bw->ei_start = a_bw->ei_node->key.object_id;

    // skinny/normal extent item
    if (a_bw->ei_node->key.item_type == BTRFS_ITEM_TYPE_METADATA_ITEM)
        a_bw->ei_end = a_bw->ei_start + a_bw->btrfs->sb->leafsize;
    else
        a_bw->ei_end = a_bw->ei_start + a_bw->ei_node->key.offset;

    a_bw->ei_flags = TSK_FS_BLOCK_FLAG_ALLOC;
    if (ei.flags & BTRFS_EXTENT_ITEM_FLAGS_DATA)
        a_bw->ei_flags = (TSK_FS_BLOCK_FLAG_ENUM) (a_bw->ei_flags | TSK_FS_BLOCK_FLAG_CONT);
    if (ei.flags & BTRFS_EXTENT_ITEM_FLAGS_TREE_BLOCK)
        a_bw->ei_flags = (TSK_FS_BLOCK_FLAG_ENUM) (a_bw->ei_flags | TSK_FS_BLOCK_FLAG_META);
}


/**
 * Ensures that the current extent data covers a logical address or otherwise lies before or after it
 * @param a_bw pointer to blockwalk structure
 * @param a_block_address logical address
 * @return true if no error occured, otherwise false
 */
static bool
btrfs_blockwalk_ensure_extent_data(BTRFS_BLOCKWALK * a_bw,
    const TSK_DADDR_T a_block_address)
{
    // if we already have a node
    if (a_bw->ei_node) {
        // if the next extent item is needed, fetch it (if existing)
        if (!a_bw->no_more_ei && a_block_address >= a_bw->ei_end) {
            BTRFS_TREENODE_RESULT node_result = btrfs_treenode_step(a_bw->btrfs, &a_bw->ei_node, &a_bw->ei_key,
                    BTRFS_CMP_IGNORE_OBJID | BTRFS_CMP_IGNORE_LSB_TYPE | BTRFS_CMP_IGNORE_OFFSET, BTRFS_LAST, BTRFS_STEP_INITIAL | BTRFS_STEP_REPEAT);
            if (node_result == BTRFS_TREENODE_ERROR) {
                tsk_error_errstr2_concat("- btrfs_blockwalk_invoke: stepping to next extent item");
                return false;
            }
            if (node_result == BTRFS_TREENODE_NOT_FOUND)
                a_bw->no_more_ei = true;
            if (node_result == BTRFS_TREENODE_FOUND)
                btrfs_blockwalk_apply_extent_item(a_bw);
        }
        return true;
    }


    /* try to get an extent item
     *   a) whose address (= object ID) equals the block's address OR OTHERWISE
     *   b) being the next left neighbour of a (non-existing) a)
     * which of both exactly applies will be handled by the final address comparison
     */
    a_bw->ei_key.object_id = a_block_address;
    BTRFS_TREENODE_RESULT node_result = btrfs_treenode_search(a_bw->btrfs, &a_bw->ei_node, a_bw->btrfs->extent_tree_root_node_address, &a_bw->ei_key,
            BTRFS_CMP_IGNORE_LSB_TYPE | BTRFS_CMP_IGNORE_OFFSET, BTRFS_SEARCH_ALLOW_LEFT_NEIGHBOUR);
    if (node_result == BTRFS_TREENODE_ERROR) {
        tsk_error_errstr2_concat("- btrfs_blockwalk_retrieve_initial_node: loading extent item");
        return false;
    }
    if (node_result == BTRFS_TREENODE_FOUND) {
        // ensure that in case b) the selected item is an extent item
        node_result = btrfs_treenode_step(a_bw->btrfs, &a_bw->ei_node, &a_bw->ei_key,
                BTRFS_CMP_IGNORE_OBJID | BTRFS_CMP_IGNORE_LSB_TYPE | BTRFS_CMP_IGNORE_OFFSET, BTRFS_FIRST, BTRFS_STEP_REPEAT);
        if (node_result == BTRFS_TREENODE_ERROR) {
            tsk_error_errstr2_concat("- btrfs_blockwalk_retrieve_initial_node: stepping to previous extent item");
            return false;
        }
        if (node_result == BTRFS_TREENODE_FOUND) {
            btrfs_blockwalk_apply_extent_item(a_bw);
            return true;
        }
    }

    /* neither a) or b) applies, so we know that the current address is not covered by any extent item - therefore prepare for next invokation:
     * now we can only get an extent item
     *   c) being the next right neighbour of a (non-existing) a)
     * this is exactly fulfilled by the very first extent item in the tree, so fetch it
     * (such an item definitely exists, as there are at least the default trees using allocated space)
     */
    btrfs_treenode_free(a_bw->ei_node);
    a_bw->ei_node = btrfs_treenode_extremum(a_bw->btrfs, a_bw->btrfs->extent_tree_root_node_address, BTRFS_FIRST);
    if (!a_bw->ei_node)
        return false;

    node_result = btrfs_treenode_step(a_bw->btrfs, &a_bw->ei_node, &a_bw->ei_key,
            BTRFS_CMP_IGNORE_OBJID | BTRFS_CMP_IGNORE_LSB_TYPE | BTRFS_CMP_IGNORE_OFFSET, BTRFS_LAST, BTRFS_STEP_REPEAT);
    if (node_result == BTRFS_TREENODE_ERROR) {
        tsk_error_errstr2_concat("- btrfs_blockwalk_retrieve_initial_node: stepping to first extent item");
        return false;
    }
    if (node_result == BTRFS_TREENODE_NOT_FOUND) {
        btrfs_error(TSK_ERR_FS_CORRUPT, "btrfs_blockwalk_retrieve_initial_node: no extent items found");
        return false;
    }

    btrfs_blockwalk_apply_extent_item(a_bw);
    return true;
}


/**
 * Tries to map a physical address to a logical address.
 * @param a_bw pointer to blockwalk structure
 * @param a_block_address pointer to address
 * @return true if the address could be mapped, otherwise false
 */
static bool
btrfs_blockwalk_apply_mapping(BTRFS_BLOCKWALK * a_bw,
    TSK_DADDR_T * a_block_address)
{
    // if no more cached chunks abort
    if (a_bw->no_more_cc)
        return false;

    // if valid cached chunk is current or next, try to map
    if (a_bw->cc && btrfs_chunk_remaining_bytes(a_bw->cc, *a_block_address) > 0)
        return btrfs_chunk_map(a_bw->cc, *a_block_address, a_block_address);


    // derive next cached chunk (thereby try to map)
    a_bw->cc = NULL;
    bool result = btrfs_address_map(&a_bw->btrfs->chunks->phys2log, &a_bw->cc, *a_block_address, a_block_address);

    // reset extent data (in case of current logical address smaller than previous one)
    btrfs_treenode_free(a_bw->ei_node);
    a_bw->ei_node = NULL;
    a_bw->no_more_ei = false;

    // check if no more cached chunks
    if (!a_bw->cc)
        a_bw->no_more_cc = true;

    return result;
}


/**
 * Returns the block flags of the next block.
 * @param a_bw pointer to blockwalk structure
 * @return flags of the current block if no error occured, otherwise TSK_FS_BLOCK_FLAG_UNUSED
 */
static TSK_FS_BLOCK_FLAG_ENUM
btrfs_blockwalk_invoke(BTRFS_BLOCKWALK * a_bw)
{
    // early block increment for next invokation
    TSK_DADDR_T block_address = a_bw->block++ * a_bw->btrfs->fs_info.block_size;

    // check for superblocks (which are not covered by extent tree)
    if (btrfs_superblock_includes_address(block_address))
        return (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_META);

    // handle phys->log mapping
//  btrfs_debug("### address before: 0x%" PRIxDADDR "\n", block_address);
    if (!btrfs_blockwalk_apply_mapping(a_bw, &block_address))
        return TSK_FS_BLOCK_FLAG_UNALLOC;
//  btrfs_debug("### address after: 0x%" PRIxDADDR "\n", block_address);

    // ensure correct extent data
    if (!btrfs_blockwalk_ensure_extent_data(a_bw, block_address))
        return TSK_FS_BLOCK_FLAG_UNUSED;

    // if block address within extent item range, return regarding flags
    return (block_address >= a_bw->ei_start && block_address < a_bw->ei_end) ?
            a_bw->ei_flags : TSK_FS_BLOCK_FLAG_UNALLOC;
}


/**
 * Returns the block flags of the specified physical block
 * @param a_fs FS info
 * @param a_addr physical block
 * @return flags of the block if no error occured, otherwise TSK_FS_BLOCK_FLAG_UNUSED
 */
static TSK_FS_BLOCK_FLAG_ENUM
btrfs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs;

    // single blockwalk invokation
    BTRFS_BLOCKWALK *bw = btrfs_blockwalk_alloc(btrfs, a_addr);
    TSK_FS_BLOCK_FLAG_ENUM result = btrfs_blockwalk_invoke(bw);
    btrfs_blockwalk_free(bw);

    return result;
}


/**
 * Iterates through a range of physical blocks and calls the callback with the content and the allocation status of each desired block.
 * @param a_fs FS info
 * @param a_start_blk physical start block
 * @param a_end_blk physical end block
 * @param a_flags flags
 * @param a_action pointer to callback
 * @param a_ptr pointer to opaque callback data
 * @return 0 if no error occured, otherwise 1
 */
static uint8_t
btrfs_block_walk(TSK_FS_INFO * a_fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr)
{
    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs;
    TSK_FS_BLOCK *block;
    uint8_t result = 0;

    // clean up any error messages that are lying around
    tsk_error_reset();

    // sanity checks
    if (a_start_blk < a_fs->first_block || a_start_blk > a_fs->last_block) {
        btrfs_error(TSK_ERR_FS_WALK_RNG,
                "btrfs_block_walk: start block: %" PRIuDADDR, a_start_blk);
        return 1;
    }
    if (a_end_blk < a_fs->first_block || a_end_blk > a_fs->last_block || a_end_blk < a_start_blk) {
        btrfs_error(TSK_ERR_FS_WALK_RNG,
                "btrfs_block_walk: end block: %" PRIuDADDR, a_end_blk);
        return 1;
    }

    // sanity check on a_flags
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) && ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0))
        a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM) (a_flags | TSK_FS_BLOCK_WALK_FLAG_ALLOC | TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) && ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0))
        a_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM) (a_flags | TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);

    block = tsk_fs_block_alloc(a_fs);
    if (!block)
        return 1;

    // iterate through block range
    BTRFS_BLOCKWALK *bw = btrfs_blockwalk_alloc(btrfs, a_start_blk);
    for (TSK_DADDR_T addr = a_start_blk; addr <= a_end_blk; addr++) {
        TSK_FS_BLOCK_FLAG_ENUM block_flags = btrfs_blockwalk_invoke(bw);
        if (block_flags == TSK_FS_BLOCK_FLAG_UNUSED) {
            tsk_error_errstr2_concat("- btrfs_block_walk: block %" PRIuDADDR, addr);
            result = 1;
            goto end;
        }

        // test if we should call the callback with this one
        if ((block_flags & TSK_FS_BLOCK_FLAG_META)      && !(a_flags & TSK_FS_BLOCK_WALK_FLAG_META))
            continue;
        if ((block_flags & TSK_FS_BLOCK_FLAG_CONT)      && !(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT))
            continue;
        if ((block_flags & TSK_FS_BLOCK_FLAG_ALLOC)     && !(a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC))
            continue;
        if ((block_flags & TSK_FS_BLOCK_FLAG_UNALLOC)   && !(a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC))
            continue;

        if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
            block_flags = (TSK_FS_BLOCK_FLAG_ENUM) (block_flags | TSK_FS_BLOCK_FLAG_AONLY);

        if (!tsk_fs_block_get_flag(a_fs, block, addr, block_flags)) {
            tsk_error_set_errstr2("btrfs_block_walk: block %" PRIuDADDR, addr);
            result = 1;
            goto end;
        }

        // invoke callback
        int retval = a_action(block, a_ptr);
        if (retval == TSK_WALK_STOP)
            break;
        if (retval == TSK_WALK_ERROR) {
            result = 1;
            break;
        }
    }

    // cleanup
end:
    btrfs_blockwalk_free(bw);
    tsk_fs_block_free(block);
    return result;
}



/*
 * EXTENT_DATA walk
 */


/**
 * Frees an EXTENT_DATA walk structure.
 * @param a_edw pointer to EXTENT_DATA walk structure
 */
static void
btrfs_extent_datawalk_free(BTRFS_EXTENT_DATAWALK * a_edw)
{
    if (!a_edw)
        return;

    if (a_edw->node)
        btrfs_treenode_free(a_edw->node);
    delete a_edw;
}


/**
 * Allocates an EXTENT_DATA walk structure.
 * @param a_btrfs Btrfs info
 * @param a_meta pointer to file meta structure
 * @return pointer to EXTENT_DATA walk structure if no error occured, otherwise NULL
 */
static BTRFS_EXTENT_DATAWALK *
btrfs_extent_datawalk_alloc(BTRFS_INFO * a_btrfs,
    const TSK_FS_META * a_meta)
{
    BTRFS_EXTENT_DATAWALK *edw = new BTRFS_EXTENT_DATAWALK;
    edw->btrfs = a_btrfs;
    edw->size = a_meta->size;
    edw->offset = 0;

    edw->node = NULL;

    uint64_t subvol;
    TSK_INUM_T inum;
    if (!btrfs_inum_virt2real_map(a_btrfs, a_meta->addr, &subvol, &inum)) {
        btrfs_extent_datawalk_free(edw);
        return NULL;
    }

    edw->key.object_id = inum;
    edw->key.item_type = BTRFS_ITEM_TYPE_EXTENT_DATA;
    edw->key.offset = 0;

    // get first item (if it exists)
    BTRFS_TREENODE_RESULT node_result = btrfs_treenode_search_lowest(edw->btrfs, &edw->node, btrfs_subvol_tree_address(edw->btrfs, subvol), &edw->key,
            BTRFS_CMP_IGNORE_OFFSET);
    if (node_result == BTRFS_TREENODE_ERROR) {
        tsk_error_set_errstr2("- btrfs_extentdatawalk_alloc: loading EXTENT_DATA");
        btrfs_extent_datawalk_free(edw);
        return NULL;
    }

    return edw;
}


/**
 * Gets the next (possibly emulated) EXTENT_DATA item.
 * @param a_edw pointer to EXTENT_DATA walk structure
 * @param a_ed pointer to EXTENT_DATA structure pointer
 * @param a_offset pointer to current offset (or NULL)
 * @return result
 */
static BTRFS_TREENODE_RESULT
btrfs_extent_datawalk_get(BTRFS_EXTENT_DATAWALK * a_edw, BTRFS_EXTENT_DATA ** a_ed, TSK_DADDR_T * a_offset)
{
    // return, if file content is already completely covered
    if (a_edw->offset >= a_edw->size)
        return BTRFS_TREENODE_NOT_FOUND;

    // if no more item, ensure block size alignment
    size_t hole_end = a_edw->node ?
            a_edw->node->key.offset : roundup(a_edw->size, a_edw->btrfs->fs_info.block_size);
    size_t hole_size = hole_end - a_edw->offset;
    BTRFS_EXTENT_DATA *ed;

    // if hole present, return emulated sparse block, otherwise real item
    if (hole_size) {
        ed = new BTRFS_EXTENT_DATA;
        memset(ed, 0x00, sizeof(BTRFS_EXTENT_DATA));

        ed->size_decoded = hole_size;
        ed->compression = BTRFS_EXTENT_DATA_COMPRESSION_NONE;
        ed->encryption = BTRFS_EXTENT_DATA_ENCRYPTION_NONE;
        ed->other_encoding = BTRFS_EXTENT_DATA_OTHER_ENCODING_NONE;
        ed->type = BTRFS_EXTENT_DATA_TYPE_REGULAR;

        ed->nrd.extent_address = 0; // sparse
        ed->nrd.extent_size = hole_size;
        ed->nrd.file_offset = 0;
        ed->nrd.file_bytes = hole_size;

        if (tsk_verbose)
            tsk_fprintf(stderr, "btrfs_extent_datawalk_get: emulated sparse run at offset %zd: n: %" PRId64 "\n",
                    a_edw->offset, ed->size_decoded);
    } else {
        ed = btrfs_extent_data_fromraw(btrfs_treenode_itemdata(a_edw->node), btrfs_treenode_itemsize(a_edw->node));
        if (!ed)
            return BTRFS_TREENODE_ERROR;

        if (tsk_verbose) {
            if (ed->type == BTRFS_EXTENT_DATA_TYPE_INLINE)
                tsk_fprintf(stderr, "btrfs_extent_datawalk_get: inline run at offset %zd: "
                        "n: %" PRId64 ", comp: 0x%" PRIx8 ", encr: 0x%" PRIx8 ", o_enc: 0x%" PRIx16 ", "
                        "data len: %" PRId32 "\n",
                        a_edw->offset, ed->size_decoded, ed->compression, ed->encryption, ed->other_encoding,
                        ed->rd.data_len);
            else {
                if (ed->nrd.extent_address)
                    tsk_fprintf(stderr, "btrfs_extent_datawalk_get: regular run at offset %zd: "
                            "n: %" PRId64 ", comp: 0x%" PRIx8 ", encr: 0x%" PRIx8 ", o_enc: 0x%" PRIx16 ", "
                            "ea: 0x%" PRIx64 ", es: %" PRId64 ", o: 0x%" PRIx64 ", s: %" PRId64 "\n",
                            a_edw->offset, ed->size_decoded, ed->compression, ed->encryption, ed->other_encoding,
                            ed->nrd.extent_address, ed->nrd.extent_size, ed->nrd.file_offset, ed->nrd.file_bytes);
                else
                    tsk_fprintf(stderr, "btrfs_extent_datawalk_get: sparse run at offset %zd: "
                            "n: %" PRId64 ", comp: 0x%" PRIx8 ", encr: 0x%" PRIx8 ", o_enc: 0x%" PRIx16 ", "
                            "es: %" PRId64 ", o: 0x%" PRIx64 ", s: %" PRId64 "\n",
                            a_edw->offset, ed->size_decoded, ed->compression, ed->encryption, ed->other_encoding,
                            ed->nrd.extent_size, ed->nrd.file_offset, ed->nrd.file_bytes);
            }
        }

        // step to next item
        BTRFS_TREENODE_RESULT node_result = btrfs_treenode_step(a_edw->btrfs, &a_edw->node, &a_edw->key,
                BTRFS_CMP_IGNORE_OFFSET, BTRFS_LAST, BTRFS_STEP_INITIAL);
        if (node_result == BTRFS_TREENODE_ERROR) {
            tsk_error_errstr2_concat("- btrfs_extentdatawalk_get: stepping to next EXTENT_DATA item");
            btrfs_extent_data_free(ed);
            return BTRFS_TREENODE_ERROR;
        }
        if (node_result == BTRFS_TREENODE_NOT_FOUND) {
            btrfs_treenode_free(a_edw->node);
            a_edw->node = NULL;
        }
    }

    *a_ed = ed;
    if (a_offset)
        *a_offset = a_edw->offset;

    a_edw->offset += btrfs_extent_data_size(ed);
    return BTRFS_TREENODE_FOUND;
}



/*
 * inode walk
 */


/**
 * Maps the stored inode file type to a TSK_FS_META_TYPE
 * @param a_mode inode file type
 * @return result
 */
static inline TSK_FS_META_TYPE_ENUM
btrfs_mode2metatype(const uint32_t a_mode)
{
    // type is embedded into mode field like defined in stat.h
    switch (a_mode & BTRFS_S_IFMT) {
    case BTRFS_S_IFSOCK:
        return TSK_FS_META_TYPE_SOCK;
    case BTRFS_S_IFLNK:
        return TSK_FS_META_TYPE_LNK;
    case BTRFS_S_IFREG:
        return TSK_FS_META_TYPE_REG;
    case BTRFS_S_IFBLK:
        return TSK_FS_META_TYPE_BLK;
    case BTRFS_S_IFDIR:
        return TSK_FS_META_TYPE_DIR;
    case BTRFS_S_IFCHR:
        return TSK_FS_META_TYPE_CHR;
    case BTRFS_S_IFIFO:
        return TSK_FS_META_TYPE_FIFO;
    default:
        return TSK_FS_META_TYPE_UNDEF;
    }
}


/**
 * Maps the stored inode file mode to a TSK_FS_META_MODE
 * @param a_mode inode file mode
 * @return result
 */
static inline TSK_FS_META_MODE_ENUM
btrfs_mode2metamode(const uint32_t a_mode)
{
    TSK_FS_META_MODE_ENUM result = (TSK_FS_META_MODE_ENUM) 0;

    if (a_mode & BTRFS_S_ISUID)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_ISUID);
    if (a_mode & BTRFS_S_ISGID)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_ISGID);
    if (a_mode & BTRFS_S_ISVTX)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_ISVTX);

    if (a_mode & BTRFS_S_IRUSR)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IRUSR);
    if (a_mode & BTRFS_S_IWUSR)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IWUSR);
    if (a_mode & BTRFS_S_IXUSR)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IXUSR);

    if (a_mode & BTRFS_S_IRGRP)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IRGRP);
    if (a_mode & BTRFS_S_IWGRP)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IWGRP);
    if (a_mode & BTRFS_S_IXGRP)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IXGRP);

    if (a_mode & BTRFS_S_IROTH)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IROTH);
    if (a_mode & BTRFS_S_IWOTH)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IWOTH);
    if (a_mode & BTRFS_S_IXOTH)
        result = (TSK_FS_META_MODE_ENUM) (result | TSK_FS_META_MODE_IXOTH);

    return result;
}


/**
 * Allocates an inodewalk structure
 * @param a_btrfs Btrfs info
 * @param a_start_vinum virtual inum to start the inodewalk with
 * @return pointer to inodewalk structure
 */
static BTRFS_INODEWALK *
btrfs_inodewalk_alloc(BTRFS_INFO * a_btrfs, const uint64_t a_start_vinum)
{
    BTRFS_INODEWALK *iw = new BTRFS_INODEWALK;
    iw->btrfs = a_btrfs;
    iw->vinum = a_start_vinum;
    iw->subvol = 0;

    iw->key.item_type = BTRFS_ITEM_TYPE_INODE_ITEM;
    iw->key.offset = 0;
    iw->node = NULL;
    return iw;
}


/**
 * Frees an inodewalk structure
 * @param a_iw pointer to inodewalk structure
 */
static void
btrfs_inodewalk_free(BTRFS_INODEWALK * a_iw)
{
    if (!a_iw)
        return;

    if (a_iw->node)
        btrfs_treenode_free(a_iw->node);
    delete a_iw;
}


/**
 * Returns the inode flags (except TSK_FS_META_FLAG_COMP) of the next inode
 * @param a_iw pointer to inodewalk structure
 * @return flags of the current inode if no error occured, otherwise 0
 */
static TSK_FS_META_FLAG_ENUM
btrfs_inodewalk_invoke(BTRFS_INODEWALK * a_iw)
{
    // early virtual inum increment for next invokation
    TSK_INUM_T current_vinum = a_iw->vinum++;

    // handle special virtual inums
    if (current_vinum > a_iw->btrfs->fs_info.last_inum - BTRFS_VINUM_COUNT_SPECIAL)
        return (TSK_FS_META_FLAG_ENUM) (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED);

    uint64_t subvol;
    TSK_INUM_T inum;
    if (!btrfs_inum_virt2real_map(a_iw->btrfs, current_vinum, &subvol, &inum)) {
        tsk_error_set_errstr2("btrfs_inodewalk_invoke: mapping inum of virtual inum: %" PRIuINUM, current_vinum);
        return (TSK_FS_META_FLAG_ENUM) 0;
    }
    a_iw->key.object_id = inum;

    // if subvol changed, reset treenode
    if (a_iw->subvol != subvol) {
        a_iw->subvol = subvol;

        btrfs_treenode_free(a_iw->node);
        a_iw->node = NULL;
    }

    // if no node, retrieve it, otherwise step to next INODE_ITEM - all this works due to the continuous virtual inum mapping
    BTRFS_TREENODE_RESULT node_result;
    if (!a_iw->node)
        node_result = btrfs_treenode_search(a_iw->btrfs, &a_iw->node, btrfs_subvol_tree_address(a_iw->btrfs, a_iw->subvol), &a_iw->key,
                0, 0);
    else
        node_result = btrfs_treenode_step(a_iw->btrfs, &a_iw->node, &a_iw->key,
                0, BTRFS_LAST, BTRFS_STEP_INITIAL | BTRFS_STEP_REPEAT);
    if (node_result == BTRFS_TREENODE_ERROR) {
        tsk_error_errstr2_concat("- btrfs_inodewalk_invoke: %s INODE_ITEM item of virtual inum: %" PRIuINUM,
                a_iw->node ? "stepping to current" : "loading", current_vinum);
        return (TSK_FS_META_FLAG_ENUM) 0;
    }
    if (node_result == BTRFS_TREENODE_NOT_FOUND) {
        btrfs_error(TSK_ERR_FS_INODE_COR, "btrfs_inodewalk_invoke: could not %s virtual inum: %" PRIuINUM,
                a_iw->node ? "step to" : "find", current_vinum);
        return (TSK_FS_META_FLAG_ENUM) 0;
    }

    // retrieve inode data
    btrfs_inode_rawparse(btrfs_treenode_itemdata(a_iw->node), &a_iw->ii);
#ifdef BTRFS_DEBUG
    btrfs_inode_debugprint(&a_iw->ii);
#endif

    return (TSK_FS_META_FLAG_ENUM) (TSK_FS_META_FLAG_USED |
            (a_iw->ii.nlink ? TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC));
}


/**
 * Fills the meta structure with the regarding data of the current inode (possibly adds TSK_FS_META_FLAG_COMP to the flags)
 * @param a_iw pointer to inodewalk structure
 * @param a_flags inode flags derived from previous btrfs_inodewalk_invoke call
 * @param a_meta pointer to file meta structure
 * @return true if no error occured, otherwise false
 */
static bool
btrfs_inodewalk_fillmeta(BTRFS_INODEWALK * a_iw,
    const TSK_FS_META_FLAG_ENUM a_flags, TSK_FS_META * a_meta)
{
    TSK_FS_INFO *fs = &a_iw->btrfs->fs_info;
    TSK_INUM_T current_vinum = a_iw->vinum - 1; // -1 to undo the early increment

    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_inodewalk_fillmeta: Filling meta structure of inum: %" PRIuINUM "\n", current_vinum);

    // handle orphan files dir
    if (current_vinum == TSK_FS_ORPHANDIR_INUM(fs))
        return tsk_fs_dir_make_orphan_dir_meta(fs, a_meta) == 0;

    a_meta->addr = current_vinum;
    a_meta->flags = a_flags;

    a_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (a_meta->attr)
        tsk_fs_attrlist_markunused(a_meta->attr);

    if (a_meta->link) {
        free(a_meta->link);
        a_meta->link = NULL;
    }

    // init custom content
    if (a_meta->content_len != BTRFS_FILE_CONTENT_LEN) {
        a_meta = tsk_fs_meta_realloc(a_meta, BTRFS_FILE_CONTENT_LEN);
        if (!a_meta)
            return false;
    }


    // handle superblock
    if (a_meta->addr == BTRFS_SUPERBLOCK_VINUM(fs)) {
        memset(a_meta->content_ptr, 0x00, a_meta->content_len);
        a_meta->size = BTRFS_SUPERBLOCK_RAWLEN;
        a_meta->type = TSK_FS_META_TYPE_VIRT;
        return true;
    }

    // store inode data for later
    memcpy(a_meta->content_ptr, &a_iw->ii, a_meta->content_len);


    a_meta->nlink = a_iw->ii.nlink;
    a_meta->gid = a_iw->ii.gid;
    a_meta->uid = a_iw->ii.uid;

    a_meta->type = btrfs_mode2metatype(a_iw->ii.mode);
    a_meta->mode = btrfs_mode2metamode(a_iw->ii.mode);

    // stored dir size is twice the total char number of all entries filenames, so leave it at 0
    if (a_meta->type != TSK_FS_META_TYPE_DIR)
        a_meta->size = a_iw->ii.size;

    a_meta->atime = a_iw->ii.atime.seconds;
    a_meta->atime_nano = a_iw->ii.atime.nanoseconds;
    a_meta->ctime = a_iw->ii.ctime.seconds;
    a_meta->ctime_nano = a_iw->ii.ctime.nanoseconds;
    a_meta->mtime = a_iw->ii.mtime.seconds;
    a_meta->mtime_nano = a_iw->ii.mtime.nanoseconds;


    /*
     * - if non-empty regular file, check for at least one non-raw extent
     * - if symlink, derive link name
     * => early exit, if neither applies
     */
    if (!((a_meta->type == TSK_FS_META_TYPE_REG && a_meta->size) || a_meta->type == TSK_FS_META_TYPE_LNK))
        return true;

    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_inodewalk_fillmeta: Checking EXTENT_DATA item(s) of inum: %" PRIuINUM "\n", current_vinum);

    // iterate over all EXTENT_DATA items
    BTRFS_EXTENT_DATAWALK *edw = btrfs_extent_datawalk_alloc(a_iw->btrfs, a_meta);
    if (!edw)
        return false;

    for (;;) {
        // next EXTENT_DATA
        BTRFS_EXTENT_DATA *ed;
        BTRFS_TREENODE_RESULT node_result = btrfs_extent_datawalk_get(edw, &ed, NULL);
        if (node_result == BTRFS_TREENODE_ERROR) {
            tsk_error_set_errstr2("btrfs_inodewalk_fillmeta: getting next EXTENT_DATA item");
            btrfs_extent_datawalk_free(edw);
            return false;
        }
        if (node_result == BTRFS_TREENODE_NOT_FOUND)
            break;

#ifdef BTRFS_DEBUG
        btrfs_extent_data_debugprint(ed);
#endif

        bool ed_is_raw = BTRFS_EXTENT_DATA_IS_RAW(ed);

        // if symlink, handle target + break
        if (a_meta->type == TSK_FS_META_TYPE_LNK) {
            if (!ed_is_raw) {
                btrfs_error(TSK_ERR_FS_INODE_COR,
                        "btrfs_inodewalk_fillmeta: non-raw symlink target of virtual inum: %" PRIuINUM, current_vinum);
                btrfs_extent_data_free(ed);
                btrfs_extent_datawalk_free(edw);
                return false;
            }

            size_t target_len = ed->rd.data_len;
            a_meta->link = (char*) tsk_malloc(target_len + 1);
            if (!a_meta->link) {
                tsk_error_set_errstr2("btrfs_inodewalk_fillmeta: setting target of virtual inum: %" PRIuINUM, current_vinum);
                btrfs_extent_data_free(ed);
                btrfs_extent_datawalk_free(edw);
                return false;
            }
            memcpy(a_meta->link, ed->rd.data, target_len);
            a_meta->link[target_len] = 0x00;    // terminator

            btrfs_debug("symlink target of inode 0x%" PRIxINUM " is '%s'\n", a_meta->addr, a_meta->link);

            btrfs_extent_data_free(ed);
            break;
        }

        btrfs_extent_data_free(ed);

        // set flag + break
        if (!ed_is_raw) {
            a_meta->flags = (TSK_FS_META_FLAG_ENUM) (a_meta->flags | TSK_FS_META_FLAG_COMP);
            break;
        }
    };

    btrfs_extent_datawalk_free(edw);
    return true;
}


/**
 * Populates the meta structure of a file
 * @param a_fs FS info
 * @param a_fs_file pointer to file structure
 * @param a_addr virtual inum
 * @return 0 if no error occured, otherwise 1
 */
static uint8_t
btrfs_file_add_meta(TSK_FS_INFO * a_fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T a_addr)
{
    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    // sanity check
    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        btrfs_error(TSK_ERR_FS_INODE_NUM,
                "btrfs_file_add_meta: 0x%" PRIxINUM " too large/small", a_addr);
        return 1;
    }

    if (!a_fs_file) {
        btrfs_error(TSK_ERR_FS_ARG,
                "btrfs_file_add_meta: a_fs_file is NULL");
        return 1;
    }
    if (!a_fs_file->meta) {
        a_fs_file->meta = tsk_fs_meta_alloc(BTRFS_FILE_CONTENT_LEN);
        if (!a_fs_file->meta)
            return 1;
    } else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    // load inode info
    BTRFS_INODEWALK *iw = btrfs_inodewalk_alloc(btrfs, a_addr);

    TSK_FS_META_FLAG_ENUM inode_flags = btrfs_inodewalk_invoke(iw);
    if (inode_flags == (TSK_FS_META_FLAG_ENUM) 0) {
        btrfs_inodewalk_free(iw);
        return 1;
    }

    if (!btrfs_inodewalk_fillmeta(iw, inode_flags, a_fs_file->meta)) {
        btrfs_inodewalk_free(iw);
        return 1;
    }

    btrfs_inodewalk_free(iw);
    return 0;
}


/**
 * Iterates through a range of inodes and calls the callback with the inode of each desired inode.
 * @param a_fs FS info
 * @param a_start_inum start virtual inum
 * @param a_end_inum end virtual inum
 * @param a_flags flags
 * @param a_action pointer to callback
 * @param a_ptr pointer to opaque callback data
 * @return 0 if no error occured, otherwise 1
 */
static uint8_t
btrfs_inode_walk(TSK_FS_INFO * a_fs, TSK_INUM_T a_start_inum,
    TSK_INUM_T a_end_inum, TSK_FS_META_FLAG_ENUM a_flags,
    TSK_FS_META_WALK_CB a_action, void *a_ptr)
{
    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    // sanity checks
    if (a_start_inum < a_fs->first_inum || a_start_inum > a_fs->last_inum) {
        btrfs_error(TSK_ERR_FS_WALK_RNG,
                "btrfs_inode_walk: start inode: %" PRIuINUM "", a_start_inum);
        return 1;
    }

    if (a_end_inum < a_fs->first_inum || a_end_inum > a_fs->last_inum || a_end_inum < a_start_inum) {
        btrfs_error(TSK_ERR_FS_WALK_RNG,
                "btrfs_inode_walk: end inode: %" PRIuINUM "", a_end_inum);
        return 1;
    }

    // if ORPHAN is wanted, then make sure that the flags are correct
    if (a_flags & TSK_FS_META_FLAG_ORPHAN) {
        a_flags = (TSK_FS_META_FLAG_ENUM) (a_flags | TSK_FS_META_FLAG_UNALLOC | TSK_FS_META_FLAG_USED);
        a_flags = (TSK_FS_META_FLAG_ENUM) (a_flags & ~TSK_FS_META_FLAG_ALLOC & ~TSK_FS_META_FLAG_UNUSED);

        if (tsk_fs_dir_load_inum_named(a_fs) != TSK_OK) {
            tsk_error_errstr2_concat("- btrfs_inode_walk: identifying inodes allocated by file names");
            return 1;
        }
    } else {
        // sanity check on flags
        if (((a_flags & TSK_FS_META_FLAG_ALLOC) == 0) && ((a_flags & TSK_FS_META_FLAG_UNALLOC) == 0))
            a_flags = (TSK_FS_META_FLAG_ENUM) (a_flags | TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
        if (((a_flags & TSK_FS_META_FLAG_USED) == 0) && ((a_flags & TSK_FS_META_FLAG_UNUSED) == 0))
            a_flags = (TSK_FS_META_FLAG_ENUM) (a_flags | TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
    }

    TSK_FS_FILE *file = tsk_fs_file_alloc(a_fs);
    if (!file)
        return 1;

    file->meta = tsk_fs_meta_alloc(BTRFS_FILE_CONTENT_LEN);
    if (!file->meta) {
        tsk_fs_file_close(file);
        return 1;
    }

    // iterate through inode range
    uint8_t result = 0;
    BTRFS_INODEWALK *iw = btrfs_inodewalk_alloc(btrfs, a_start_inum);
    for (TSK_INUM_T inum = a_start_inum; inum <= a_end_inum; inum++) {
        TSK_FS_META_FLAG_ENUM inode_flags = btrfs_inodewalk_invoke(iw);
        if (inode_flags == (TSK_FS_META_FLAG_ENUM) 0) {
            result = 1;
            break;
        }

        // test if we should call the callback with this one
        if ((inode_flags & TSK_FS_META_FLAG_ALLOC)      && !(a_flags & TSK_FS_META_FLAG_ALLOC))
            continue;
        if ((inode_flags & TSK_FS_META_FLAG_UNALLOC)        && !(a_flags & TSK_FS_META_FLAG_UNALLOC))
            continue;
        if ((inode_flags & TSK_FS_META_FLAG_USED)       && !(a_flags & TSK_FS_META_FLAG_USED))
            continue;
        if ((inode_flags & TSK_FS_META_FLAG_UNUSED)     && !(a_flags & TSK_FS_META_FLAG_UNUSED))
            continue;

        // if we want only orphans, then check if this inode is in the seen list
        if ((inode_flags & TSK_FS_META_FLAG_UNALLOC) && (a_flags & TSK_FS_META_FLAG_ORPHAN) &&
                tsk_fs_dir_find_inum_named(a_fs, inum))
            continue;

        tsk_fs_meta_reset(file->meta);
        if (!btrfs_inodewalk_fillmeta(iw, inode_flags, file->meta)) {
            result = 1;
            break;
        }

        // invoke callback
        int retval = a_action(file, a_ptr);
        if (retval == TSK_WALK_STOP)
            break;
        if (retval == TSK_WALK_ERROR) {
            result = 1;
            break;
        }
    }

    // cleanup
    btrfs_inodewalk_free(iw);
    tsk_fs_file_close(file);
    return result;
}



/*
 * directory
 */


// maps the stored dir file type to a TSK_FS_NAME_TYPE
#define BTRFS_TYPE2NAMETYPE_COUNT 8
static const TSK_FS_NAME_TYPE_ENUM btrfs_type2nametype[BTRFS_TYPE2NAMETYPE_COUNT] = {
    TSK_FS_NAME_TYPE_UNDEF,
    TSK_FS_NAME_TYPE_REG,
    TSK_FS_NAME_TYPE_DIR,
    TSK_FS_NAME_TYPE_CHR,
    TSK_FS_NAME_TYPE_BLK,
    TSK_FS_NAME_TYPE_FIFO,
    TSK_FS_NAME_TYPE_SOCK,
    TSK_FS_NAME_TYPE_LNK,
};


/**
 * Opens a directory by virtual inum
 * @param a_fs FS info
 * @param a_fs_dir pointer to a directory pointer (directory pointer may be NULL)
 * @param a_addr virtual inum
 * @param recursion_depth - ignored
 * @return result
 */
static TSK_RETVAL_ENUM
btrfs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir, TSK_INUM_T a_addr, [[maybe_unused]] int recursion_depth)
{
    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        btrfs_error(TSK_ERR_FS_WALK_RNG,
                "btrfs_dir_open_meta: Invalid inode value: %" PRIuINUM, a_addr);
        return TSK_ERR;
    }
    if (!a_fs_dir) {
        btrfs_error(TSK_ERR_FS_ARG,
                "btrfs_dir_open_meta: NULL fs_dir argument given");
        return TSK_ERR;
    }

    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs;
    TSK_FS_DIR *fs_dir = *a_fs_dir;

    bool dir_alloced;
    TSK_FS_NAME *fs_name = NULL;
    TSK_DADDR_T tree_address;
    BTRFS_TREENODE *node = NULL;
    BTRFS_TREENODE_RESULT node_result;
    BTRFS_DIR_ENTRY *de = NULL;

    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
        fs_dir->addr = a_addr;
        dir_alloced = false;
    } else {
        *a_fs_dir = fs_dir = tsk_fs_dir_alloc(a_fs, a_addr, 128);
        if (!fs_dir)
            return TSK_ERR;
        dir_alloced = true;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_dir_open_meta: Processing directory %" PRIuINUM "\n", a_addr);

    // handle the orphan directory if its contents were requested
    if (a_addr == TSK_FS_ORPHANDIR_INUM(a_fs))
        return tsk_fs_dir_find_orphans(a_fs, fs_dir);

    fs_name = tsk_fs_name_alloc(BTRFS_NAME_LEN_MAX, 0);
    if (!fs_name)
        return TSK_ERR;

    fs_dir->fs_file = tsk_fs_file_open_meta(a_fs, NULL, a_addr);
    if (!fs_dir->fs_file) {
        tsk_error_errstr2_concat(" - btrfs_dir_open_meta");
        goto on_error;
    }

    // abort, if not a dir
    if (fs_dir->fs_file->meta->type != TSK_FS_META_TYPE_DIR) {
        btrfs_error(TSK_ERR_FS_ARG, "btrfs_dir_open_meta: not a directory");
        goto on_error;
    }


    uint64_t subvol;
    TSK_INUM_T inum;
    if (!btrfs_inum_virt2real_map(btrfs, fs_dir->addr, &subvol, &inum)) {
        tsk_error_set_errstr2("btrfs_dir_open_meta: mapping inum of dir");
        goto on_error;
    }
    tree_address = btrfs_subvol_tree_address(btrfs, subvol);



    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_dir_open_meta: Creating . and .. entries\n");

    // add "." entry
    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
    fs_name->meta_addr = fs_dir->addr;
    strcpy(fs_name->name, ".");
    fs_name->type = TSK_FS_NAME_TYPE_DIR;

    if (tsk_fs_dir_add(fs_dir, fs_name)) {
        tsk_error_set_errstr2("btrfs_dir_open_meta: adding '.' dir entry");
        goto on_error;
    }


    // add ".." entry
    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
    fs_name->meta_addr = fs_dir->addr;  // fallback value, if no matching INODE_REF exists (e.g. orphan dir)
    strcpy(fs_name->name, "..");
    fs_name->type = TSK_FS_NAME_TYPE_DIR;

    // search INODE_REF - as dirs have no hardlinks, this retrieves the one and only INODE_REF (if it exists at all)
    BTRFS_KEY key;
    key.object_id = inum;
    key.item_type = BTRFS_ITEM_TYPE_INODE_REF;
    key.offset = 0; // not used, except at debug output

    node_result = btrfs_treenode_search(btrfs, &node, tree_address, &key,
            BTRFS_CMP_IGNORE_OFFSET, 0);
    if (node_result == BTRFS_TREENODE_ERROR) {
        tsk_error_set_errstr2("btrfs_dir_open_meta: loading INODE_REF item");
        goto on_error;
    }
    if (node_result == BTRFS_TREENODE_FOUND) {
        if (!btrfs_inum_real2virt_map(btrfs, subvol, node->key.offset, &fs_name->meta_addr)) {
            tsk_error_set_errstr2("btrfs_dir_open_meta: mapping inum of INODE_REF item");
            goto on_error;
        }

        btrfs_treenode_free(node);
        node = NULL;
    }

    if (tsk_fs_dir_add(fs_dir, fs_name)) {
        tsk_error_set_errstr2("btrfs_dir_open_meta: adding '..' dir entry");
        goto on_error;
    }


    // get first DIR_INDEX item
    key.item_type = BTRFS_ITEM_TYPE_DIR_INDEX;
    key.offset = 0;

    node_result = btrfs_treenode_search_lowest(btrfs, &node, tree_address, &key,
            BTRFS_CMP_IGNORE_OFFSET);
    if (node_result == BTRFS_TREENODE_ERROR) {
        tsk_error_set_errstr2("btrfs_dir_open_meta: loading DIR_INDEX item");
        goto on_error;
    }

    // iterate
    while (node_result == BTRFS_TREENODE_FOUND) {
        de = btrfs_dir_entry_fromraw(btrfs_treenode_itemdata(node), btrfs_treenode_itemsize(node));
        if (de->next) {
            btrfs_error(TSK_ERR_FS_INODE_COR,
                    "btrfs_dir_open_meta: DIR_INDEX item with more than one entry");
            goto on_error;
        }

        if (tsk_verbose)
            tsk_fprintf(stderr, "btrfs_dir_open_meta: Processing DIR_INDEX: %" PRId64 "\n", node->key.offset);
#ifdef BTRFS_DEBUG
        btrfs_debug("### DIR_INDEX ###\n");
        btrfs_dir_entry_debugprint(de);
#endif

        // apply data
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        if (strlen(de->name) > fs_name->name_size) {
            memcpy(fs_name->name, de->name, fs_name->name_size);
            fs_name->name[fs_name->name_size] = 0;  // terminator
        } else {
            strcpy(fs_name->name, de->name);
        }
        fs_name->type = btrfs_type2nametype[de->type < BTRFS_TYPE2NAMETYPE_COUNT ? de->type : 0];

        // derive target virtual inum
        switch (de->child.item_type) {
        case BTRFS_ITEM_TYPE_INODE_ITEM:
            // ordinary file/dir
            if (!btrfs_inum_real2virt_map(btrfs, subvol, de->child.object_id, &fs_name->meta_addr)) {
                tsk_error_set_errstr2("btrfs_dir_open_meta: mapping inum of INODE_ITEM item");
                goto on_error;
            }
            break;
        case BTRFS_ITEM_TYPE_ROOT_ITEM: {
            // subvolume
            uint64_t new_subvol = de->child.object_id;
            if (!btrfs_inum_real2virt_map(btrfs, new_subvol, btrfs_subvol_root_inum(btrfs, new_subvol), &fs_name->meta_addr)) {
                tsk_error_set_errstr2("btrfs_dir_open_meta: mapping inum of ROOT_ITEM item");
                goto on_error;
            }
            break; }
        default:
            btrfs_error(TSK_ERR_FS_INODE_COR,
                    "btrfs_dir_open_meta: DIR_INDEX item with unsupported child item type: 0x%" PRIx8, de->child.item_type);
            goto on_error;
        }

        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_error_set_errstr2("btrfs_dir_open_meta: adding dir entry");
            goto on_error;
        }

        btrfs_dir_entry_free(de);
        de = NULL;

        // next DIR_INDEX
        node_result = btrfs_treenode_step(btrfs, &node, &key,
                BTRFS_CMP_IGNORE_OFFSET, BTRFS_LAST, BTRFS_STEP_INITIAL);
        if (node_result == BTRFS_TREENODE_ERROR) {
            tsk_error_set_errstr2("btrfs_dir_open_meta: stepping to next DIR_INDEX item");
            goto on_error;
        }
    }

    btrfs_treenode_free(node);
    node = NULL;


    // if root virtual inum, add special virtual inums
    if (fs_dir->addr == btrfs->fs_info.root_inum) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "btrfs_dir_open_meta: Creating superblock file and orphan files dir entries\n");

        // superblock
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        fs_name->meta_addr = BTRFS_SUPERBLOCK_VINUM(a_fs);
        strcpy(fs_name->name, BTRFS_SUPERBLOCK_NAME);
        fs_name->type = TSK_FS_NAME_TYPE_VIRT;

        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_error_set_errstr2("btrfs_dir_open_meta: adding superblock dir entry");
            goto on_error;
        }

        // orphan files
        if (tsk_fs_dir_make_orphan_dir_name(a_fs, fs_name)) {
            tsk_error_set_errstr2("btrfs_dir_open_meta: making orphan files dir entry");
            goto on_error;
        }
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_error_set_errstr2("btrfs_dir_open_meta: adding orphan files dir entry");
            goto on_error;
        }
    }

    tsk_fs_name_free(fs_name);
    return TSK_OK;

on_error:
    if (dir_alloced) {
        tsk_fs_dir_close(fs_dir);
        *a_fs_dir = NULL;
    } else {
        tsk_fs_file_close(fs_dir->fs_file);
    }
    tsk_fs_name_free(fs_name);
    btrfs_treenode_free(node);
    btrfs_dir_entry_free(de);
    return TSK_ERR;
}


/**
 * Compares two names.
 * @param a_fs_info FS info
 * @param a_name_a name A
 * @param a_name_b name B
 * @return relation between name A and name B
 */
static int
btrfs_name_cmp([[maybe_unused]] TSK_FS_INFO * a_fs_info, const char *a_name_a,
    const char *a_name_b)
{
    return strcmp(a_name_a, a_name_b);
}



/*
 * attribute data
 */


#ifdef BTRFS_COMP_SUPPORT
/**
 * Tries to read a (non-)resident block into the input buffer
 * @param a_dw pointer to datawalk structure
 * @return amount of read bytes if no error occured, otherwise -1
 */
static ssize_t
btrfs_datawalk_ed_read_rawblock(BTRFS_DATAWALK * a_dw)
{
    TSK_DADDR_T block_size = a_dw->btrfs->fs_info.block_size;
    size_t read_bytes = MIN(a_dw->ed_raw_size - a_dw->ed_raw_offset, block_size);

    if (read_bytes == 0)
        return -1;

    if (a_dw->ed_resident) {
        // resident
        memcpy(a_dw->in_blockbuffer, a_dw->ed->rd.data + a_dw->ed_raw_offset, read_bytes);
    } else {
        // non-resident
        TSK_DADDR_T address_log = a_dw->ed->nrd.extent_address + a_dw->ed_raw_offset;
        TSK_DADDR_T address_phys;

        // if logical address not in cached chunk range, derive new cached chunk
        if (!(a_dw->cc && btrfs_chunk_map(a_dw->cc, address_log, &address_phys))) {
            if (!btrfs_address_map(&a_dw->btrfs->chunks->log2phys, &a_dw->cc, address_log, &address_phys)) {
                btrfs_error(TSK_ERR_FS_BLK_NUM,
                        "btrfs_datawalk_ed_read_rawblock: Could not map logical address: 0x%" PRIxDADDR, address_log);
                return -1;
            }
        }

        ssize_t result = tsk_fs_read(&a_dw->btrfs->fs_info, address_phys, (char*) a_dw->in_blockbuffer, read_bytes);
        if (result != (ssize_t) read_bytes) {
            if (result != -1)
                btrfs_error(TSK_ERR_FS_READ,
                        "btrfs_datawalk_ed_read_rawblock: Got less bytes than requested: %zd of %zd", result, read_bytes);
            return -1;
        }

        a_dw->last_raw_addr = address_phys;
    }
    a_dw->ed_raw_offset += read_bytes;
    return read_bytes;
}


#ifdef HAVE_LIBZ
/**
 * Tries to read a specific byte amount at the current offset within the zlib compressed EXTENT_ITEM
 * @param a_dw pointer to datawalk structure
 * @param a_data pointer to data
 * @param a_len data len
 * @return amount of read bytes if no error occured, otherwise -1
 */
static ssize_t
btrfs_datawalk_ed_read_zlib(BTRFS_DATAWALK * a_dw, uint8_t * a_data,
    const size_t a_len)
{
    size_t read_bytes = MIN(a_len, a_dw->ed_out_size - a_dw->ed_out_offset);

    a_dw->zlib_state.next_out = a_data;
    a_dw->zlib_state.avail_out = read_bytes;

    while (a_dw->zlib_state.avail_out) {
        // if necessary, refill input buffer
        if (a_dw->zlib_state.avail_in == 0) {
            ssize_t result = btrfs_datawalk_ed_read_rawblock(a_dw);
            if (result == -1)
                return -1;
            if (result == 0)
                break;

            a_dw->zlib_state.next_in = a_dw->in_blockbuffer;
            a_dw->zlib_state.avail_in = result;
        }

        // inflate
        int zlib_result = inflate(&a_dw->zlib_state, Z_SYNC_FLUSH);
        if (zlib_result == Z_STREAM_END)
            break;
        if (zlib_result != Z_OK) {
            btrfs_error(TSK_ERR_FS_READ, "btrfs_datawalk_ed_read_zlib: zlib error: %s (%d)",
                    a_dw->zlib_state.msg ? a_dw->zlib_state.msg : "", zlib_result);
            return -1;
        }
    }

    return read_bytes - a_dw->zlib_state.avail_out;
}
#endif


/**
 * Tries to read a specific byte amount at the current offset within the EXTENT_ITEM
 * @param a_dw pointer to datawalk structure
 * @param a_data pointer to data (or NULL to just skip)
 * @param a_len data len
 * @return amount of read bytes if no error occured, otherwise -1
 */
static ssize_t
btrfs_datawalk_ed_read(BTRFS_DATAWALK * a_dw, uint8_t * a_data,
    const size_t a_len)
{
    TSK_DADDR_T block_size = a_dw->btrfs->fs_info.block_size;
    size_t available_bytes = a_dw->ed_out_size - a_dw->ed_out_offset;
    size_t read_bytes = MIN(a_len, available_bytes);

    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_datawalk_ed_read: %s %zd bytes of data at offset: %zd\n",
                a_data ? "Reading" : "Skipping", read_bytes, a_dw->ed_offset + a_dw->ed_out_offset);

    // shortcut return, if we should skip the whole EXTENT_ITEM - also at unsupported compression/encryption/encoding!
    if (!a_data && read_bytes == available_bytes) {
        a_dw->ed_out_offset += read_bytes;
        return read_bytes;
    }

    size_t read_result = 0;
    switch (a_dw->ed_type) {
    case BTRFS_ED_TYPE_SPARSE:
        if (a_data)
            memset(a_data, 0x00, read_bytes);
        read_result = read_bytes;
        break;
    case BTRFS_ED_TYPE_RAW: {
        if (!a_data)
            read_result = read_bytes;
        while (read_result < read_bytes) {
            // round down to corresponding block address
            size_t inblock_offset = (a_dw->ed_out_offset + read_result) % block_size;
            a_dw->ed_raw_offset = (a_dw->ed_out_offset + read_result) - inblock_offset;

            ssize_t result = btrfs_datawalk_ed_read_rawblock(a_dw);
            if (result == -1)
                return -1;

            size_t needed_bytes_part = read_bytes - read_result;
            size_t read_bytes_part = MIN(needed_bytes_part, result - inblock_offset);
            memcpy(a_data + read_result, a_dw->in_blockbuffer + inblock_offset, read_bytes_part);
            read_result += read_bytes_part;

            if (read_bytes_part < needed_bytes_part)
                break;
        }
        break;  }
#ifdef HAVE_LIBZ
    case BTRFS_ED_TYPE_COMP_ZLIB: {
        while (read_result < read_bytes) {
            // skipping is done blockwise into a temporary buffer
            size_t read_bytes_part = a_data ? read_bytes : MIN(read_bytes - read_result, block_size);

            ssize_t result = btrfs_datawalk_ed_read_zlib(a_dw, a_data ? a_data : a_dw->tmp_blockbuffer, read_bytes_part);
            if (result == -1)
                return -1;
            read_result += result;

            if (result != (ssize_t) read_bytes_part)
                break;
        }
        break;  }
#endif
    default:
        btrfs_error(TSK_ERR_FS_MAGIC,
                "btrfs_datawalk_ed_read: EXTENT_ITEM with unsupported compression/encryption/encoding mode: 0x%x 0x%x 0x%x",
                a_dw->ed->compression, a_dw->ed->encryption, a_dw->ed->other_encoding);
        return -1;
    }

    // success
    a_dw->ed_out_offset += read_result;
    return read_result;
}


/**
 * Initializes internal values with the current EXTENT_DATA item
 * @param a_dw pointer to a datawalk structure
 * @return true if no error occured, otherwise false
 */
static bool
btrfs_datawalk_ed_init(BTRFS_DATAWALK * a_dw)
{
#ifdef BTRFS_DEBUG
    btrfs_extent_data_debugprint(a_dw->ed);
#endif

    a_dw->ed_resident = a_dw->ed->type == BTRFS_EXTENT_DATA_TYPE_INLINE;

    // retrieve type
    if (BTRFS_EXTENT_DATA_IS_RAW(a_dw->ed)) {
        a_dw->ed_type = (!a_dw->ed_resident && a_dw->ed->nrd.extent_address == 0) ?
                BTRFS_ED_TYPE_SPARSE : BTRFS_ED_TYPE_RAW;
    } else {
        a_dw->ed_type = BTRFS_ED_TYPE_UNKNOWN;  // we don't abort here, because later maybe the whole EXTENT_ITEM is skipped
#ifdef HAVE_LIBZ
        if (    a_dw->ed->compression == BTRFS_EXTENT_DATA_COMPRESSION_ZLIB &&
                a_dw->ed->encryption == BTRFS_EXTENT_DATA_ENCRYPTION_NONE &&
                a_dw->ed->other_encoding == BTRFS_EXTENT_DATA_OTHER_ENCODING_NONE)
            a_dw->ed_type = BTRFS_ED_TYPE_COMP_ZLIB;
#endif
    }

    a_dw->ed_raw_offset = 0;
    a_dw->ed_out_offset = 0;

    if (a_dw->ed_resident) {
        a_dw->ed_raw_size = a_dw->ed->rd.data_len;
        a_dw->ed_out_size = a_dw->ed->size_decoded;
    } else {
        a_dw->ed_raw_size = a_dw->ed->nrd.extent_size;
        a_dw->ed_out_size = MIN(a_dw->ed->nrd.file_bytes, a_dw->size - a_dw->ed_offset);
    }

#ifdef HAVE_LIBZ
    // if needed, (re)init zlib
    if (a_dw->ed_type == BTRFS_ED_TYPE_COMP_ZLIB) {
        a_dw->zlib_state.next_in = Z_NULL;
        a_dw->zlib_state.avail_in = 0;

        int zlib_result;
        if (a_dw->zlib_state_used)
            zlib_result = inflateReset(&a_dw->zlib_state);
        else {
            zlib_result = inflateInit(&a_dw->zlib_state);
            a_dw->zlib_state_used = true;
        }

        if (zlib_result != Z_OK) {
            btrfs_error(TSK_ERR_FS_READ, "btrfs_datawalk_ed_init: zlib error: %s (%d)",
                    a_dw->zlib_state.msg ? a_dw->zlib_state.msg : "", zlib_result);
            return false;
        }
    }
#endif

    // skip offset within extent
    size_t skip_offset = a_dw->ed->nrd.file_offset;
    if (!a_dw->ed_resident && skip_offset) {
        a_dw->ed_out_size += skip_offset;

        ssize_t result = btrfs_datawalk_ed_read(a_dw, NULL, skip_offset);
        if (result != (ssize_t) skip_offset) {
            if (result != -1)
                btrfs_error(TSK_ERR_FS_READ,
                        "btrfs_datawalk_ed_init: Got less bytes than requested: %zd of %zd", result, skip_offset);
            return false;
        }
    }

    return true;
}


/**
 * Frees a datawalk structure
 * @param a_dw pointer to a datawalk structure
 */
static void
btrfs_datawalk_free(BTRFS_DATAWALK * a_dw)
{
    if (!a_dw)
        return;

    btrfs_extent_data_free(a_dw->ed);
    btrfs_extent_datawalk_free(a_dw->edw);

#ifdef HAVE_LIBZ
    if (a_dw->zlib_state_used)
        inflateEnd(&a_dw->zlib_state);  // ignore possible error
#endif

    delete[] a_dw->tmp_blockbuffer;
    delete[] a_dw->in_blockbuffer;

    delete a_dw;
}


/**
 * Allocates a datawalk structure
 * @param a_fs_attr pointer to a file attribute
 * @return pointer to datawalk structure if no error occured, otherwise NULL
 */
static BTRFS_DATAWALK *
btrfs_datawalk_alloc(const TSK_FS_ATTR * a_fs_attr)
{
    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs_attr->fs_file->fs_info;

    BTRFS_DATAWALK *dw = new BTRFS_DATAWALK;
    dw->attr = a_fs_attr;
    dw->btrfs = btrfs;
    dw->size = dw->attr->fs_file->meta->size;   // attr->size can't be used, because compressed resident attributes have wrong size
    dw->cc = NULL;

    dw->in_blockbuffer = new uint8_t[btrfs->fs_info.block_size];
    dw->tmp_blockbuffer = new uint8_t[btrfs->fs_info.block_size];

#ifdef HAVE_LIBZ
    dw->zlib_state_used = false;
    dw->zlib_state.zalloc = Z_NULL;
    dw->zlib_state.zfree = Z_NULL;
    dw->zlib_state.opaque = Z_NULL;
#endif

    dw->ed = NULL;
    dw->edw = btrfs_extent_datawalk_alloc(btrfs, dw->attr->fs_file->meta);
    if (!dw->edw) {
        btrfs_datawalk_free(dw);
        return NULL;
    }

    return dw;
}


/**
 * Tries to read a specific byte amount at the current offset within the attribute data
 * @param a_dw pointer to datawalk structure
 * @param a_data pointer to data (or NULL to just skip)
 * @param a_len data len
 * @return amount of read bytes if no error occured, otherwise -1
 */
static ssize_t
btrfs_datawalk_read(BTRFS_DATAWALK * a_dw, uint8_t * a_data, const size_t a_len)
{
    size_t written = 0;
    while (written < a_len) {
        // if no EXTENT_DATA item yet or end of current one reached, get next one
        if (!a_dw->ed || a_dw->ed_out_offset == a_dw->ed_out_size) {
            btrfs_extent_data_free(a_dw->ed);
            a_dw->ed = NULL;

            BTRFS_TREENODE_RESULT node_result = btrfs_extent_datawalk_get(a_dw->edw, &a_dw->ed, &a_dw->ed_offset);
            if (node_result == BTRFS_TREENODE_ERROR) {
                tsk_error_set_errstr2("- btrfs_datawalk_read: getting next EXTENT_DATA item");
                return -1;
            }
            if (node_result == BTRFS_TREENODE_NOT_FOUND)
                break;

            if (!btrfs_datawalk_ed_init(a_dw))
                return -1;
        }

        ssize_t result = btrfs_datawalk_ed_read(a_dw, a_data + written, a_len - written);
        if (result == -1)
            return -1;

        written += result;
    }
    return written;
}


/**
 * Reads a specific byte amount at a specific byte offset within the attribute data
 * @param a_fs_attr pointer to a file attribute
 * @param a_offset offset
 * @param a_buf pointer to buffer
 * @param a_len data len   (>=0 due to size_t being unsigned)
 * @return amount of read bytes if no error occured, otherwise -1
 */
static ssize_t
btrfs_file_read_special(const TSK_FS_ATTR * a_fs_attr, TSK_OFF_T a_offset,
    char *a_buf, size_t a_len)
{
    // check params
    if (!a_fs_attr || !a_fs_attr->fs_file || !a_fs_attr->fs_file->meta || !a_fs_attr->fs_file->fs_info || !a_buf) {
        btrfs_error(TSK_ERR_FS_ARG, "btrfs_file_read_special: called with NULL pointers");
        return -1;
    }
    if (!(a_fs_attr->flags & TSK_FS_ATTR_COMP)) {
        btrfs_error(TSK_ERR_FS_ARG, "btrfs_file_read_special: called with non-special attribute");
        return -1;
    }
    if (a_offset >= a_fs_attr->size || a_offset < 0) {
        btrfs_error(TSK_ERR_FS_ARG, "btrfs_file_read_special: called with read offset out of range");
        return -1;
    }
    if (a_offset + (TSK_OFF_T) a_len > a_fs_attr->size ) {
        btrfs_error(TSK_ERR_FS_ARG, "btrfs_file_read_special: called with read len out of range");
        return -1;
    }


    BTRFS_DATAWALK *dw = btrfs_datawalk_alloc(a_fs_attr);
    if (!dw) {
        return -1;
    }

    // skip offset
    ssize_t result;

    if (a_offset) {
        result = btrfs_datawalk_read(dw, NULL, a_offset);
        if (result != (ssize_t) a_offset) {
            if (result != -1)
                btrfs_error(TSK_ERR_FS_READ,
                        "btrfs_file_read_special: Got less offset bytes than requested: %zd of %" PRIdOFF,
                        result, a_offset);
            btrfs_datawalk_free(dw);
            return -1;
        }
    }

    // read into buffer
    result = btrfs_datawalk_read(dw, (uint8_t*) a_buf, a_len);

    btrfs_datawalk_free(dw);
    return result;
}


/**
 * Maps the stored EXTENT_DATA type to a TSK_FS_BLOCK_FLAG
 * @param a_ed_type EXTENT_DATA type
 * @return result
 */
static inline TSK_FS_BLOCK_FLAG_ENUM
btrfs_edtype2blockflag(const BTRFS_ED_TYPE a_ed_type)
{
    switch (a_ed_type) {
    case BTRFS_ED_TYPE_RAW:
        return TSK_FS_BLOCK_FLAG_RAW;
    case BTRFS_ED_TYPE_SPARSE:
        return TSK_FS_BLOCK_FLAG_SPARSE;
#ifdef HAVE_LIBZ
    case BTRFS_ED_TYPE_COMP_ZLIB:
        return TSK_FS_BLOCK_FLAG_COMP;
#endif
    default:
        return (TSK_FS_BLOCK_FLAG_ENUM) 0;
    }
}


/**
 * Iterates through all blocks of an attribute and calls the callback with each block (block size less/equal FS block size)
 * @param a_fs_attr pointer to a file attribute
 * @param a_flags flags
 * @param a_action pointer to callback
 * @param a_ptr pointer to opaque callback data
 * @return 0 if no error occured, otherwise 1
 */
static uint8_t
btrfs_attr_walk_special(const TSK_FS_ATTR * a_fs_attr, int a_flags,
    TSK_FS_FILE_WALK_CB a_action, void *a_ptr)
{
    // check params
    if (!a_fs_attr || !a_fs_attr->fs_file || !a_fs_attr->fs_file->meta || !a_fs_attr->fs_file->fs_info || !a_action) {
        btrfs_error(TSK_ERR_FS_ARG, "btrfs_attr_walk_special: called with NULL pointers");
        return 1;
    }
    if (!(a_fs_attr->flags & TSK_FS_ATTR_COMP)) {
        btrfs_error(TSK_ERR_FS_ARG, "btrfs_attr_walk_special: called with non-special attribute");
        return 1;
    }


    BTRFS_DATAWALK *dw = btrfs_datawalk_alloc(a_fs_attr);
    if (!dw)
        return 1;

    const size_t block_size = a_fs_attr->fs_file->fs_info->block_size;
    //uint8_t block[a_fs_attr->fs_file->fs_info->block_size];
    uint8_t *block = new uint8_t[block_size];
    uint8_t *used_block = a_flags & TSK_FS_FILE_WALK_FLAG_AONLY ? NULL : block;

    ssize_t result;
    for (TSK_OFF_T offset = 0; offset < dw->size; offset += result) {
        size_t read_bytes = 0;
        if (dw->size < offset ) {
            read_bytes = 0;
        }
        else {
            read_bytes = dw->size - offset;
        }
        if (read_bytes > block_size) {
            read_bytes = block_size;
        }

        // read block
        result = btrfs_datawalk_read(dw, used_block, read_bytes);
        if (result != (ssize_t) read_bytes) {
            if (result != -1)
                btrfs_error(TSK_ERR_FS_READ,
                        "btrfs_attr_walk_special: Got less bytes than requested: %zd of %zd", result, read_bytes);
            btrfs_datawalk_free(dw);
            return 1;
        }

        TSK_FS_BLOCK_FLAG_ENUM flags = (TSK_FS_BLOCK_FLAG_ENUM)
                (TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_CONT | btrfs_edtype2blockflag(dw->ed_type));
        if (dw->ed_resident)
            flags = (TSK_FS_BLOCK_FLAG_ENUM) (flags | TSK_FS_BLOCK_FLAG_RES);

        // if sparse block and sparse blocks unwanted, skip block
        if ((flags & TSK_FS_BLOCK_FLAG_SPARSE) && (a_flags & TSK_FS_FILE_WALK_FLAG_NOSPARSE))
            continue;

        // invoke callback
        TSK_DADDR_T raw_addr = !(flags & TSK_FS_BLOCK_FLAG_RES) && (flags & TSK_FS_BLOCK_FLAG_RAW) ?
                dw->last_raw_addr : 0;
        TSK_WALK_RET_ENUM cb_result = a_action(a_fs_attr->fs_file, offset, raw_addr, (char*) used_block, result, flags, a_ptr);
        if (cb_result == TSK_WALK_ERROR) {
            btrfs_datawalk_free(dw);
            delete[] block;
            return 1;
        }
        if (cb_result == TSK_WALK_STOP)
            break;
    }

    btrfs_datawalk_free(dw);
    delete[] block;
    return 0;
}
#else
static ssize_t
btrfs_file_read_special(const TSK_FS_ATTR * a_fs_attr, TSK_OFF_T a_offset,
    char *a_buf, size_t a_len)
{
    btrfs_error(TSK_ERR_FS_UNSUPFUNC,
            "btrfs_file_read_special: no supported compression available");
    return -1;
}


static uint8_t
btrfs_attr_walk_special(const TSK_FS_ATTR * a_fs_attr, int a_flags,
    TSK_FS_FILE_WALK_CB a_action, void *a_ptr)
{
    btrfs_error(TSK_ERR_FS_UNSUPFUNC,
            "btrfs_attr_walk_special: no supported compression available");
    return 1;
}
#endif


/**
 * Returns the default attribute type
 * @param a_file FS info
 * @return default attribute type
 */
static TSK_FS_ATTR_TYPE_ENUM
btrfs_get_default_attr_type([[maybe_unused]] const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}


/**
 * Loads the attributes of a file
 * @param a_fs_file pointer to file
 * @return 0 if no error occured, otherwise 1
 */
static uint8_t
btrfs_load_attrs(TSK_FS_FILE * a_fs_file)
{
    if (!a_fs_file || !a_fs_file->meta || !a_fs_file->fs_info) {
        btrfs_error(TSK_ERR_FS_ARG, "btrfs_load_attrs: called with NULL pointers");
        return 1;
    }

    TSK_FS_INFO *fs = a_fs_file->fs_info;
    BTRFS_INFO *btrfs = (BTRFS_INFO*) fs;
    TSK_FS_META *meta = a_fs_file->meta;
    bool comp = meta->flags & TSK_FS_META_FLAG_COMP;

    TSK_FS_ATTR *attr = NULL;
    BTRFS_TREENODE *node = NULL;
    BTRFS_TREENODE_RESULT node_result;
    BTRFS_DIR_ENTRY *de = NULL;
    BTRFS_EXTENT_DATAWALK *edw = NULL;
    BTRFS_EXTENT_DATA *ed = NULL;
    TSK_FS_ATTR_RUN *run = NULL;

    if (meta->attr && meta->attr_state == TSK_FS_META_ATTR_STUDIED)
        return 0;
    if (meta->attr_state == TSK_FS_META_ATTR_ERROR)
        return 1;

    if (meta->attr)
        tsk_fs_attrlist_markunused(meta->attr);
    else {
        meta->attr = tsk_fs_attrlist_alloc();
        if (!meta->attr)
            return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_load_attrs: Loading attributes of inum: %" PRIuINUM "\n", meta->addr);


    // handle special virtual inums
    if (meta->addr == BTRFS_SUPERBLOCK_VINUM(fs)) {
        TSK_DADDR_T sb_address = btrfs_superblock_address(btrfs->sb_mirror_index);
        // uint8_t tmp_sb[meta->size];
        uint8_t *tmp_sb = new uint8_t[meta->size];

        ssize_t result = tsk_fs_read(fs, sb_address, (char*) tmp_sb, meta->size);
        if (result != (signed) meta->size) {
            if (result >= 0)
                btrfs_error(TSK_ERR_FS_READ, "btrfs_load_attrs: Error reading superblock at physical address: 0x%" PRIxDADDR, sb_address);
            else
                tsk_error_set_errstr2("btrfs_load_attrs: Error reading superblock at physical address: 0x%" PRIxDADDR, sb_address);
            delete[] tmp_sb;
            goto on_error;
        }

        attr = tsk_fs_attrlist_getnew(meta->attr, TSK_FS_ATTR_RES);
        if (!attr) {
            tsk_error_set_errstr2("btrfs_load_attrs: Error getting attribute for superblock");
            delete[] tmp_sb;
            goto on_error;
        }
        if (tsk_fs_attr_set_str(a_fs_file, attr, NULL,
                fs->get_default_attr_type(a_fs_file), TSK_FS_ATTR_ID_DEFAULT, tmp_sb, meta->size)) {
            tsk_error_set_errstr2("btrfs_load_attrs: Error setting attribute for superblock");
            delete[] tmp_sb;
            goto on_error;
        }
        delete[] tmp_sb;

        if (tsk_verbose)
            tsk_fprintf(stderr, "btrfs_load_attrs: Added superblock standard attribute (%" PRIdOFF " bytes)\n", meta->size);
        return 0;
    }
    if (meta->addr == TSK_FS_ORPHANDIR_INUM(fs)) {
        meta->attr_state = TSK_FS_META_ATTR_STUDIED;
        return 0;
    }


    uint64_t subvol;
    TSK_INUM_T inum;
    if (!btrfs_inum_virt2real_map(btrfs, meta->addr, &subvol, &inum)) {
        tsk_error_set_errstr2("btrfs_load_attrs: mapping inum of file");
        goto on_error;
    }


    // derive XATTR_ITEM items, if existing
    BTRFS_KEY key;
    key.object_id = inum;
    key.item_type = BTRFS_ITEM_TYPE_XATTR_ITEM;
    key.offset = 0;

    node_result = btrfs_treenode_search_lowest(btrfs, &node, btrfs_subvol_tree_address(btrfs, subvol), &key,
            BTRFS_CMP_IGNORE_OFFSET);
    if (node_result == BTRFS_TREENODE_ERROR) {
        tsk_error_errstr2_concat("- btrfs_load_attrs: loading XATTR_ITEM item");
        goto on_error;
    }
    if (node_result == BTRFS_TREENODE_FOUND) {
        uint8_t dummy[1];

        // iterate over all XATTR_ITEM items
        do {
            de = btrfs_dir_entry_fromraw(btrfs_treenode_itemdata(node), btrfs_treenode_itemsize(node));
#ifdef BTRFS_DEBUG
            btrfs_debug("### XATTR_ITEM ###\n");
            btrfs_dir_entry_debugprint(de);
#endif

            // iterate over all entries
            for (BTRFS_DIR_ENTRY *de_entry = de; de_entry; de_entry = de_entry->next) {
                attr = tsk_fs_attrlist_getnew(meta->attr, TSK_FS_ATTR_RES);
                if (!attr) {
                    tsk_error_set_errstr2("btrfs_load_attrs: Error getting attribute for extended attribute");
                    goto on_error;
                }

                uint8_t *res_data = de_entry->data_len ? de_entry->data : dummy;
                if (tsk_fs_attr_set_str(a_fs_file, attr, de_entry->name,
                        TSK_FS_ATTR_TYPE_UNIX_XATTR, TSK_FS_ATTR_ID_DEFAULT,
                        res_data, de_entry->data_len)) {
                    tsk_error_set_errstr2("btrfs_load_attrs: Error setting attribute for extended attribute");
                    goto on_error;
                }

                if (tsk_verbose)
                    tsk_fprintf(stderr, "btrfs_load_attrs: Added extended attribute '%s' (%" PRIdOFF " bytes)\n",
                            attr->name, attr->size);
                attr = NULL;
            }

            btrfs_dir_entry_free(de);
            de = NULL;

            // next XATTR_ITEM
            node_result = btrfs_treenode_step(btrfs, &node, &key,
                    BTRFS_CMP_IGNORE_OFFSET, BTRFS_LAST, BTRFS_STEP_INITIAL);
            if (node_result == BTRFS_TREENODE_ERROR) {
                tsk_error_set_errstr2("btrfs_load_attrs: stepping to next XATTR_ITEM item");
                goto on_error;
            }
        } while (node_result == BTRFS_TREENODE_FOUND);

        btrfs_treenode_free(node);
        node = NULL;
    }


    // derive EXTENT_DATA items, if existing
    edw = btrfs_extent_datawalk_alloc(btrfs, meta);
    if (!edw)
        goto on_error;

    for (;;) {
        // next EXTENT_DATA
        TSK_DADDR_T ed_offset;
        node_result = btrfs_extent_datawalk_get(edw, &ed, &ed_offset);
        if (node_result == BTRFS_TREENODE_ERROR) {
            tsk_error_set_errstr2("btrfs_load_attrs: getting next EXTENT_DATA item");
            goto on_error;
        }
        if (node_result == BTRFS_TREENODE_NOT_FOUND)
            break;

#ifdef BTRFS_DEBUG
        btrfs_extent_data_debugprint(ed);
#endif

        // create attribute at first iteration
        if (!attr) {
            bool resident = ed->type == BTRFS_EXTENT_DATA_TYPE_INLINE;
            attr = tsk_fs_attrlist_getnew(meta->attr,
                    resident ? TSK_FS_ATTR_RES : TSK_FS_ATTR_NONRES);
            if (!attr) {
                tsk_error_set_errstr2("btrfs_load_attrs: Error getting attribute");
                goto on_error;
            }

            if (resident) {
                // init for resident file + add data
                uint8_t dummy[1];
                uint8_t *res_data = comp ? dummy : ed->rd.data;
                size_t len = comp ? 0 : ed->rd.data_len;
                if (tsk_fs_attr_set_str(a_fs_file, attr, NULL,
                        fs->get_default_attr_type(a_fs_file), TSK_FS_ATTR_ID_DEFAULT,
                        res_data, len)) {
                    tsk_error_set_errstr2("btrfs_load_attrs: Error setting resident attribute");
                    goto on_error;
                }
            } else {
                // init for non-resident file (no slack space at compressed files)
                TSK_OFF_T alloc_size = comp ? meta->size : roundup(meta->size, fs->block_size);
                if (tsk_fs_attr_set_run(a_fs_file, attr, NULL, NULL,
                        fs->get_default_attr_type(a_fs_file), TSK_FS_ATTR_ID_DEFAULT,
                        meta->size, meta->size, alloc_size, TSK_FS_ATTR_FLAG_NONE, 0)) {
                    tsk_error_set_errstr2("btrfs_load_attrs: Error setting non-resident attribute");
                    goto on_error;
                }
            }

            if (comp) {
                attr->flags = (TSK_FS_ATTR_FLAG_ENUM) (attr->flags | TSK_FS_ATTR_COMP);
                attr->r = btrfs_file_read_special;
                attr->w = btrfs_attr_walk_special;
            }

            if (resident) {
                btrfs_extent_data_free(ed);
                ed = NULL;
                break;
            }
        }


        // non-resident file

        bool sparse_run = ed->nrd.extent_address == 0;
        if (sparse_run)
            attr->flags = (TSK_FS_ATTR_FLAG_ENUM) (attr->flags | TSK_FS_ATTR_SPARSE);


        // if compressed attribute, abort after first sparse run (so that the attribute's sparse flag gets set)
        if (comp) {
            if (sparse_run) {
                btrfs_extent_data_free(ed);
                ed = NULL;
                break;
            }
        } else {
            // add run (respecting chunk range)

            TSK_DADDR_T run_offset = ed_offset;
            TSK_OFF_T run_len = ed->nrd.file_bytes;
            while (run_len) {
                TSK_DADDR_T run_phys_address;
                TSK_OFF_T remaining_bytes;
                TSK_FS_ATTR_RUN_FLAG_ENUM run_flag;

                // handle sparse runs
                if (sparse_run) {
                    run_phys_address = 0;
                    remaining_bytes = run_len;
                    run_flag = TSK_FS_ATTR_RUN_FLAG_SPARSE;
                } else {
                    TSK_DADDR_T run_log_address = ed->nrd.extent_address + ed->nrd.file_offset;
                    const BTRFS_CACHED_CHUNK *cc;
                    if (!btrfs_address_map(&btrfs->chunks->log2phys, &cc, run_log_address, &run_phys_address)) {
                        btrfs_error(TSK_ERR_FS_BLK_NUM,
                                "btrfs_load_attrs: Could not map logical address: 0x%" PRIxDADDR, run_log_address);
                        goto on_error;
                    }
                    remaining_bytes = btrfs_chunk_remaining_bytes(cc, run_log_address);
                    run_flag = TSK_FS_ATTR_RUN_FLAG_NONE;
                }

                TSK_OFF_T current_run_len = MIN(run_len, remaining_bytes);

                run = tsk_fs_attr_run_alloc();
                if (!run) {
                    tsk_error_set_errstr2("btrfs_load_attrs: Error allocating run");
                    goto on_error;
                }

                if (run_offset % fs->block_size) {
                    btrfs_error(TSK_ERR_FS_INODE_COR,
                            "btrfs_load_attrs: run offset not divisible by block size: 0x%" PRIxDADDR, run_offset);
                    goto on_error;
                }
                run->offset = run_offset / fs->block_size;

                if (run_phys_address % fs->block_size) {
                    btrfs_error(TSK_ERR_FS_INODE_COR,
                            "btrfs_load_attrs: run physical address not divisible by block size: 0x%" PRIxDADDR, run_phys_address);
                    goto on_error;
                }
                run->addr = run_phys_address / fs->block_size;

                if (current_run_len % fs->block_size) {
                    btrfs_error(TSK_ERR_FS_INODE_COR,
                            "btrfs_load_attrs: run len not divisible by block size: %" PRIdOFF, current_run_len);
                    goto on_error;
                }
                run->len = current_run_len / fs->block_size;

                run->flags = run_flag;
                if (tsk_fs_attr_add_run(fs, attr, run)) {
                    tsk_error_set_errstr2("btrfs_load_attrs: Error adding run");
                    goto on_error;
                }
                run = NULL;

                run_offset += current_run_len;
                run_len -= current_run_len;
            }
        }

        btrfs_extent_data_free(ed);
        ed = NULL;
    };

    btrfs_extent_datawalk_free(edw);
    edw = NULL;

    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_load_attrs: Added standard attribute (%" PRIdOFF " bytes)\n", meta->size);

    meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;

on_error:
    tsk_fs_attrlist_markunused(meta->attr);
    btrfs_treenode_free(node);
    btrfs_dir_entry_free(de);
    btrfs_extent_data_free(ed);
    btrfs_extent_datawalk_free(edw);
    tsk_fs_attr_run_free(run);

    meta->attr_state = TSK_FS_META_ATTR_ERROR;
    return 1;
}



/*
 * status
 */


/**
 * Prints data in hex notation into a file.
 * @param a_file file
 * @param a_prefix prefixed description
 * @param a_data pointer to data
 * @param a_len data len
 */
static void
btrfs_stat_output_hex(FILE * a_file, const char *a_prefix,
    const uint8_t * a_data, int a_len)
{
    tsk_fprintf(a_file, "%s: ", a_prefix);
    for (int i = 0; i < a_len; i++)
        tsk_fprintf(a_file, "%02x", *(a_data + i));
    tsk_fprintf(a_file, "\n");
}


/**
 * Prints a flag description for each set superblock compat_flags flag into a file.
 * @param a_file file
 * @param a_flags flags
 */
static void
btrfs_fsstat_print_compat_flags(FILE * a_file, uint64_t a_flags)
{
    for (int i = 0; i < 64; i++) {
        if (!(a_flags & (1ULL << i)))
            continue;

        // there are no such flags defined ATM!
        tsk_fprintf(a_file, "unknown (1 << %d)\n", i);
    }
}


/**
 * Prints a flag description for each set superblock compat_ro_flags flag into a file.
 * @param a_file file
 * @param a_flags flags
 */
static void
btrfs_fsstat_print_compat_ro_flags(FILE * a_file, uint64_t a_flags)
{
    for (int i = 0; i < 64; i++) {
        if (!(a_flags & (1ULL << i)))
            continue;

        // there are no such flags defined ATM!
        tsk_fprintf(a_file, "unknown (1 << %d)\n", i);
    }
}


/**
 * Prints a flag description for each set superblock incompat_flags flag into a file.
 * @param a_file file
 * @param a_flags flags
 */
static void
btrfs_fsstat_print_incompat_flags(FILE * a_file, uint64_t a_flags)
{
    static const char *general_flags[10] = {
        "MIXED_BACKREF",
        "DEFAULT_SUBVOL",
        "MIXED_GROUPS",
        "COMPRESS_LZO",
        "COMPRESS_LZOv2",
        "BIG_METADATA",
        "EXTENDED_IREF",
        "RAID56",
        "SKINNY_METADATA",
        "NO_HOLES"
    };

    for (int i = 0; i < 64; i++) {
        if (!(a_flags & (1ULL << i)))
            continue;

        // handle general/unknown case
        if (i < 10) {
            tsk_fprintf(a_file, "%s\n", general_flags[i]);
            continue;
        }
        tsk_fprintf(a_file, "unknown (1 << %d)\n", i);
    }
}


/**
 * Prints information about a file system into a file.
 * @param a_fs FS info
 * @param a_file file
 * @return 0 if no error occured, otherwise 1
 */
static uint8_t
btrfs_fsstat(TSK_FS_INFO * a_fs, FILE * a_file)
{
    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(a_file, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");
    tsk_fprintf(a_file, "File System Type: Btrfs\n");
    tsk_fprintf(a_file, "File System Name: %s\n", btrfs->sb->label);
    btrfs_stat_output_hex(a_file, "File System UUID",
            btrfs->sb->uuid, sizeof(btrfs->sb->uuid));
    tsk_fprintf(a_file, "\n");

    tsk_fprintf(a_file, "Used Superblock: ");
    if (!btrfs->sb_mirror_index)
        tsk_fprintf(a_file, "Original\n");
    else
        tsk_fprintf(a_file, "Mirror #%d\n", btrfs->sb_mirror_index);

    tsk_fprintf(a_file, "Flags: 0x%016" PRIx64 "\n", btrfs->sb->flags);
    tsk_fprintf(a_file, "Generation: %" PRId64 "\n", btrfs->sb->generation);
    tsk_fprintf(a_file, "\n");
    tsk_fprintf(a_file, "Total Bytes: %" PRId64 "\n", btrfs->sb->total_bytes);
    tsk_fprintf(a_file, "Bytes used: %" PRId64 "\n", btrfs->sb->bytes_used);
    tsk_fprintf(a_file, "Number of Devices: %" PRId64 "\n", btrfs->sb->num_devices);
    tsk_fprintf(a_file, "Stripe Size: %" PRId32 "\n", btrfs->sb->stripesize);
    tsk_fprintf(a_file, "\n");
    tsk_fprintf(a_file, "Checksum type: %" PRId16 " (%s)\n",
            btrfs->sb->csum_type, btrfs_csum_description(btrfs->sb->csum_type));
    tsk_fprintf(a_file, "\n");

    tsk_fprintf(a_file, "COMPATIBILITY FLAGS\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");
    tsk_fprintf(a_file, "compat_flags:\n");
    btrfs_fsstat_print_compat_flags(a_file, btrfs->sb->compat_flags);
    tsk_fprintf(a_file, "\n");
    tsk_fprintf(a_file, "compat_ro_flags:\n");
    btrfs_fsstat_print_compat_ro_flags(a_file, btrfs->sb->compat_ro_flags);
    tsk_fprintf(a_file, "\n");
    tsk_fprintf(a_file, "incompat_flags:\n");
    btrfs_fsstat_print_incompat_flags(a_file, btrfs->sb->incompat_flags);
    tsk_fprintf(a_file, "\n");

    tsk_fprintf(a_file, "METADATA INFORMATION\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");
    tsk_fprintf(a_file, "Inode Range: %" PRIuINUM " - %" PRIuINUM "\n",
            a_fs->first_inum, a_fs->last_inum);


    tsk_fprintf(a_file, "Root Directory Inode (virtual): %" PRIuINUM "\n", a_fs->root_inum);

    uint64_t subvol;
    TSK_INUM_T inum;
    if (!btrfs_inum_virt2real_map(btrfs, a_fs->root_inum, &subvol, &inum)) {
        tsk_error_set_errstr2("btrfs_fsstat: mapping root inum");
        return 1;
    }

    tsk_fprintf(a_file, "Root Directory Subvolume: 0x%" PRIx64 "\n", subvol);
    tsk_fprintf(a_file, "Root Directory Inode (real): %" PRIuINUM "\n", inum);


    tsk_fprintf(a_file, "Node Size: %" PRId32 "\n", btrfs->sb->nodesize);
    tsk_fprintf(a_file, "Leaf Size: %" PRId32 "\n", btrfs->sb->leafsize);
    tsk_fprintf(a_file, "\n");

    tsk_fprintf(a_file, "CONTENT INFORMATION\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");
    tsk_fprintf(a_file, "Block Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
            a_fs->first_block, a_fs->last_block);
    if (a_fs->last_block != a_fs->last_block_act)
        tsk_fprintf(a_file, "Total Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
                a_fs->first_block, a_fs->last_block_act);
    tsk_fprintf(a_file, "Block Size: %u\n", a_fs->block_size);
    tsk_fprintf(a_file, "\n");

    tsk_fprintf(a_file, "TREE INFORMATION\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");
    tsk_fprintf(a_file, "Logical Address of Root Tree Root: 0x%" PRIx64 "\n", btrfs->sb->root_tree_root);
    tsk_fprintf(a_file, "Root Tree Root Level: %" PRId8  "\n", btrfs->sb->root_level);
    tsk_fprintf(a_file, "\n");
    tsk_fprintf(a_file, "Logical Address of Chunk Tree Root: 0x%" PRIx64 "\n", btrfs->sb->chunk_tree_root);
    tsk_fprintf(a_file, "Chunk Root Level: %" PRId8  "\n", btrfs->sb->chunk_root_level);
    tsk_fprintf(a_file, "Chunk Root Generation: %" PRId64 "\n", btrfs->sb->chunk_root_generation);
    tsk_fprintf(a_file, "\n");
    tsk_fprintf(a_file, "Logical Address of Log Tree Root: 0x%" PRIx64 "\n", btrfs->sb->log_tree_root);
    tsk_fprintf(a_file, "Log Root Level: %" PRId8  "\n", btrfs->sb->log_root_level);
    tsk_fprintf(a_file, "Log Root Transaction ID: 0x%" PRIx64 "\n", btrfs->sb->log_root_transid);
    tsk_fprintf(a_file, "\n");

    tsk_fprintf(a_file, "VOLUME INFORMATION\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");
    tsk_fprintf(a_file, "Device ID: %"  PRId64 "\n", btrfs->sb->dev_item.device_id);
    tsk_fprintf(a_file, "Total Bytes: %" PRId64 "\n", btrfs->sb->dev_item.total_bytes);
    tsk_fprintf(a_file, "Bytes used: %" PRId64 "\n", btrfs->sb->dev_item.bytes_used);
    tsk_fprintf(a_file, "Type: 0x%" PRIx64 "\n", btrfs->sb->dev_item.type);
    tsk_fprintf(a_file, "Generation: %" PRId64 "\n", btrfs->sb->dev_item.generation);
    tsk_fprintf(a_file, "Start Offset: 0x%" PRIx64 "\n", btrfs->sb->dev_item.start_offset);
    btrfs_stat_output_hex(a_file, "Device UUID",
            btrfs->sb->dev_item.device_uuid, sizeof(btrfs->sb->dev_item.device_uuid));
    btrfs_stat_output_hex(a_file, "File System UUID",
            btrfs->sb->dev_item.fs_uuid, sizeof(btrfs->sb->dev_item.fs_uuid));
    tsk_fprintf(a_file, "\n");

    uint64_t default_subvol = btrfs_subvol_default(btrfs);
    if (!default_subvol)
        return 1;

    tsk_fprintf(a_file, "SUBVOLUME INFORMATION\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");
    tsk_fprintf(a_file, "Default subvolume: 0x%" PRIx64 "%s\n",
            default_subvol, default_subvol == BTRFS_OBJID_FS_TREE ? " (FS_TREE)" : "");
    tsk_fprintf(a_file, "\n");

    for (btrfs_subvolumes_t::iterator it = btrfs->subvolumes->begin();
            it != btrfs->subvolumes->end(); it++) {
        inum = btrfs_subvol_root_inum(btrfs, it->first);
        TSK_INUM_T vinum;
        if (!btrfs_inum_real2virt_map(btrfs, it->first, inum, &vinum)) {
            tsk_error_set_errstr2("btrfs_fsstat: mapping root inum of subvolume: 0x%" PRIx64, it->first);
            return 1;
        }

        tsk_fprintf(a_file, "Subvolume: 0x%" PRIx64 "%s\n",
                it->first, it->first == BTRFS_OBJID_FS_TREE ? " (FS_TREE)" : "");
        tsk_fprintf(a_file, "Root Directory Inode (real): %" PRIuINUM "\n", inum);
        tsk_fprintf(a_file, "Root Directory Inode (virtual): %" PRIuINUM "\n", vinum);
        tsk_fprintf(a_file, "Root address: 0x%" PRIx64 "\n", btrfs_subvol_tree_address(btrfs, it->first));
        tsk_fprintf(a_file, "Inode count: %zd\n", it->second.real2virt_inums.size());
        tsk_fprintf(a_file, "\n");
    }

    tsk_fprintf(a_file, "CACHED CHUNK INFORMATION - LOG -> PHYS\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");

    for (btrfs_cached_chunks_t::iterator it = btrfs->chunks->log2phys.begin();
            it != btrfs->chunks->log2phys.end(); it++) {
        tsk_fprintf(a_file, "Logical Address: 0x%" PRIx64 "\n", it->source_address);
        tsk_fprintf(a_file, "Size: 0x%" PRIx64 "\n", it->size);
        tsk_fprintf(a_file, "Physical Address: 0x%" PRIx64 "\n", it->target_address);
        tsk_fprintf(a_file, "\n");
    }

    tsk_fprintf(a_file, "CACHED CHUNK INFORMATION - PHYS -> LOG\n");
    tsk_fprintf(a_file, "--------------------------------------------\n");

    for (btrfs_cached_chunks_t::iterator it = btrfs->chunks->phys2log.begin();
            it != btrfs->chunks->phys2log.end(); it++) {
        if (it != btrfs->chunks->phys2log.begin())
            tsk_fprintf(a_file, "\n");
        tsk_fprintf(a_file, "Physical Address: 0x%" PRIx64 "\n", it->source_address);
        tsk_fprintf(a_file, "Size: 0x%" PRIx64 "\n", it->size);
        tsk_fprintf(a_file, "Logical Address: 0x%" PRIx64 "\n", it->target_address);
    }

    return 0;
}


// use helper callback to output used blocks
typedef struct {
    FILE *file;
    int index;
} BTRFS_ISTAT_FILEWALK_CB_HELPER;


static TSK_WALK_RET_ENUM
btrfs_istat_filewalk_cb([[maybe_unused]] TSK_FS_FILE * a_fs_file, [[maybe_unused]] TSK_OFF_T a_off,
    TSK_DADDR_T a_addr, [[maybe_unused]] char *a_buf, [[maybe_unused]] size_t a_len,
    TSK_FS_BLOCK_FLAG_ENUM a_flags, void *a_ptr)
{
    // skip resident or non-raw or blocks
    if ((a_flags & TSK_FS_BLOCK_FLAG_RES) || !(a_flags & TSK_FS_BLOCK_FLAG_RAW))
        return TSK_WALK_CONT;

    BTRFS_ISTAT_FILEWALK_CB_HELPER *helper = (BTRFS_ISTAT_FILEWALK_CB_HELPER*) a_ptr;

    tsk_fprintf(helper->file, "%" PRIuDADDR " ", a_addr);

    helper->index++;
    if (helper->index == 8) {
        tsk_fprintf(helper->file, "\n");
        helper->index = 0;
    }

    return TSK_WALK_CONT;
}


/**
 * Prints a flag description for each set inode flag into a file.
 * @param a_file file
 * @param a_flags flags
 */
static void
btrfs_istat_print_flags(FILE * a_file, uint64_t a_flags)
{
    static const char *general_flags[12] = {
        "NODATASUM",
        "NODATACOW",
        "READONLY",
        "NOCOMPRESS",
        "PREALLOC",
        "SYNC",
        "IMMUTABLE",
        "APPEND",
        "NODUMP",
        "NOATIME",
        "DIRSYNC",
        "COMPRESS"
    };

    for (int i = 0; i < 64; i++) {
        if (!(a_flags & (1ULL << i)))
            continue;

        // handle general/special/unknown case
        if (i < 12) {
            tsk_fprintf(a_file, "%s\n", general_flags[i]);
            continue;
        }
        if (i == 31) {
            tsk_fprintf(a_file, "ROOT_ITEM_INIT\n");
            continue;
        }
        tsk_fprintf(a_file, "unknown (1 << %d)\n", i);
    }
}


/**
 * Prints information about an inode into a file.
 * @param a_fs FS info
 * @param istat_flags (ignored)
 * @param a_file file
 * @param a_inum virtual inum
 * @param a_numblock number of blocks in file to force print (can go beyond file size)
 * @param a_sec_skew clock skew in seconds to also print times in
 * @return 0 if no error occured, otherwise 1
 */
static uint8_t
btrfs_istat(TSK_FS_INFO * a_fs, [[maybe_unused]] TSK_FS_ISTAT_FLAG_ENUM istat_flags, FILE * a_file, TSK_INUM_T a_inum,
            [[maybe_unused]] TSK_DADDR_T a_numblock, int32_t a_sec_skew)
{
    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs;
    TSK_FS_FILE *file;
    char ls[12];
    char time_buffer[128];

    // clean up any error messages that are lying around
    tsk_error_reset();

    file = tsk_fs_file_open_meta(a_fs, NULL, a_inum);
    if (!file)
        return 1;

    TSK_FS_META *meta = file->meta;

    bool normal_inode = a_inum <= (a_fs->last_inum - BTRFS_VINUM_COUNT_SPECIAL);
    BTRFS_INODE_ITEM *ii = (BTRFS_INODE_ITEM*) meta->content_ptr;


    tsk_fprintf(a_file, "Inode (virtual): %" PRIuINUM "\n", a_inum);

    if (normal_inode) {
        uint64_t subvol;
        TSK_INUM_T inum;
        if (!btrfs_inum_virt2real_map(btrfs, a_inum, &subvol, &inum)) {
            tsk_fs_file_close(file);
            return 1;
        }

        tsk_fprintf(a_file, "Subvolume: 0x%" PRIx64 "\n", subvol);
        tsk_fprintf(a_file, "Inode (real): %" PRIuINUM "\n", inum);
    }
    tsk_fprintf(a_file, "Allocated: %s\n",
            meta->flags & TSK_FS_META_FLAG_ALLOC ? "yes" : "no");
    tsk_fprintf(a_file, "Compressed: %s\n",
            meta->flags & TSK_FS_META_FLAG_COMP ? "yes" : "no");

    if (normal_inode)
        tsk_fprintf(a_file, "Generation: %" PRId64 "\n", ii->generation);
    if (meta->link)
        tsk_fprintf(a_file, "Symbolic Link to: %s\n", meta->link);
    tsk_fprintf(a_file, "UID / GID: %" PRIuUID " / %" PRIuGID "\n",
            meta->uid, meta->gid);

    tsk_fs_meta_make_ls(meta, ls, sizeof(ls));
    tsk_fprintf(a_file, "Mode: %s\n", ls);

    // device ids
    if (normal_inode && (meta->type == TSK_FS_META_TYPE_BLK || meta->type == TSK_FS_META_TYPE_CHR))
        tsk_fprintf(a_file, "Device Major: %" PRIu64 "   Minor: %" PRIu64 "\n",
                ii->rdev >> 20, ii->rdev & 0xFFFFF);

    tsk_fprintf(a_file, "Size: %zu\n", meta->size);
    tsk_fprintf(a_file, "Num of Links: %d\n", meta->nlink);
    tsk_fprintf(a_file, "\n");


    // print flags
    tsk_fprintf(a_file, "Flags:\n");
    if (normal_inode)
        btrfs_istat_print_flags(a_file, ii->flags);
    tsk_fprintf(a_file, "\n");


    // print times
    if (a_sec_skew) {
        tsk_fprintf(a_file, "Adjusted Inode Times:\n");

        if (meta->atime)
            meta->atime -= a_sec_skew;
        if (meta->ctime)
            meta->ctime -= a_sec_skew;
        if (meta->mtime)
            meta->mtime -= a_sec_skew;

        tsk_fprintf(a_file, "Accessed:\t%s\n",
                tsk_fs_time_to_str_subsecs(meta->atime, meta->atime_nano, time_buffer));
        tsk_fprintf(a_file, "Created:\t%s\n",
                tsk_fs_time_to_str_subsecs(meta->ctime, meta->ctime_nano, time_buffer));
        tsk_fprintf(a_file, "Modified:\t%s\n",
                tsk_fs_time_to_str_subsecs(meta->mtime, meta->mtime_nano, time_buffer));

        if (meta->atime)
            meta->atime += a_sec_skew;
        if (meta->ctime)
            meta->ctime += a_sec_skew;
        if (meta->mtime)
            meta->mtime += a_sec_skew;

        tsk_fprintf(a_file, "\n");
        tsk_fprintf(a_file, "Original Inode Times:\n");
    } else {
        tsk_fprintf(a_file, "Inode Times:\n");
    }

    tsk_fprintf(a_file, "Accessed:\t%s\n",
            tsk_fs_time_to_str_subsecs(meta->atime, meta->atime_nano, time_buffer));
    tsk_fprintf(a_file, "Created:\t%s\n",
            tsk_fs_time_to_str_subsecs(meta->ctime, meta->ctime_nano, time_buffer));
    tsk_fprintf(a_file, "Modified:\t%s\n",
            tsk_fs_time_to_str_subsecs(meta->mtime, meta->mtime_nano, time_buffer));
    tsk_fprintf(a_file, "\n");


    // print extended attributes
    tsk_fprintf(a_file, "Extended attributes:\n");
    int attribute_count = tsk_fs_file_attr_getsize(file);
    for (int i = 0; i < attribute_count; i++) {
        const TSK_FS_ATTR *attr = tsk_fs_file_attr_get_idx(file, i);
        if (!attr) {
            tsk_fs_file_close(file);
            return 1;
        }
        if (attr->type == TSK_FS_ATTR_TYPE_UNIX_XATTR)
            tsk_fprintf(a_file, "%s (%d bytes)\n", attr->name, attr->size);
    }
    tsk_fprintf(a_file, "\n");


    if (meta->type == TSK_FS_META_TYPE_REG || meta->type == TSK_FS_META_TYPE_VIRT) {
        // print blocks
        tsk_fprintf(a_file, "Blocks:\n");

        BTRFS_ISTAT_FILEWALK_CB_HELPER helper;
        helper.file = a_file;
        helper.index = 0;

        if (tsk_fs_file_walk(file, TSK_FS_FILE_WALK_FLAG_AONLY, btrfs_istat_filewalk_cb, &helper)) {
            tsk_fs_file_close(file);
            return 1;
        }
        if (helper.index)
            tsk_fprintf(a_file, "\n");
    }

    tsk_fs_file_close(file);
    return 0;
}



/*
 * unimplemented functions
 */

static uint8_t
btrfs_jentry_walk([[maybe_unused]] TSK_FS_INFO * a_fs, [[maybe_unused]] int a_entry,
    [[maybe_unused]] TSK_FS_JENTRY_WALK_CB a_cb, [[maybe_unused]] void *a_fn)
{
    btrfs_error(TSK_ERR_FS_UNSUPFUNC, "Journal support for Btrfs is not implemented");
    return 1;
}

static uint8_t
btrfs_jblk_walk([[maybe_unused]] TSK_FS_INFO * a_fs, [[maybe_unused]] TSK_DADDR_T a_daddr,
                [[maybe_unused]] TSK_DADDR_T a_daddrt, [[maybe_unused]] int a_entry, [[maybe_unused]] TSK_FS_JBLK_WALK_CB a_cb,
                [[maybe_unused]] void *a_fn)
{
    btrfs_error(TSK_ERR_FS_UNSUPFUNC, "Journal support for Btrfs is not implemented");
    return 1;
}

static uint8_t
btrfs_jopen([[maybe_unused]] TSK_FS_INFO * a_fs, [[maybe_unused]] TSK_INUM_T a_inum)
{
    btrfs_error(TSK_ERR_FS_UNSUPFUNC, "Journal support for Btrfs is not implemented");
    return 1;
}

static uint8_t
btrfs_fscheck([[maybe_unused]] TSK_FS_INFO * a_fs, [[maybe_unused]] FILE * a_file)
{
    btrfs_error(TSK_ERR_FS_UNSUPFUNC, "fscheck not implemented yet for Btrfs");
    return 1;
}



/*
 * tree printing
 */


#ifdef BTRFS_DEBUG
static void
btrfs_tree_dump(BTRFS_INFO * a_btrfs, const TSK_DADDR_T a_address,
    const char *a_description)
{
    BTRFS_TREENODE *node = NULL;

    btrfs_debug("############## dumping tree '%s' at address 0x%" PRIxDADDR " ##############\n", a_description, a_address);
    if (!btrfs_treenode_push(a_btrfs, &node, a_address, BTRFS_FIRST)) {
        tsk_error_reset();
        btrfs_debug("could not dump treelevel at address 0x%" PRIxDADDR "\n", a_address);
        return;
    }

    btrfs_tree_header_debugprint(&node->header);

    for (unsigned int i = 0; i < node->header.number_of_items; i++) {
        btrfs_debug("tree: ####### node %d #######\n", node->index);
        btrfs_key_debugprint(&node->key);

        if (node->header.level) {
            btrfs_key_pointer_rest_debugprint(&node->kp);
        } else {
            btrfs_item_rest_debugprint(&node->item);

            uint8_t *data = btrfs_treenode_itemdata(node);
            uint32_t len = btrfs_treenode_itemsize(node);

            switch (node->key.item_type) {
            case BTRFS_ITEM_TYPE_INODE_ITEM: {
                BTRFS_INODE_ITEM ii;
                btrfs_inode_rawparse(data, &ii);
                btrfs_inode_debugprint(&ii);
                break;
            }
            case BTRFS_ITEM_TYPE_INODE_REF: {
                BTRFS_INODE_REF *testref = btrfs_inode_ref_fromraw(data, len);
                btrfs_inode_ref_debugprint(testref);
                btrfs_inode_ref_free(testref);
                break;
            }
            case BTRFS_ITEM_TYPE_XATTR_ITEM: {
                BTRFS_DIR_ENTRY *de = btrfs_dir_entry_fromraw(data, len);
                btrfs_dir_entry_debugprint(de);
                btrfs_dir_entry_free(de);
                break;
            }
            case BTRFS_ITEM_TYPE_DIR_ITEM:
            case BTRFS_ITEM_TYPE_DIR_INDEX: {
                BTRFS_DIR_ENTRY *de = btrfs_dir_entry_fromraw(data, len);
                btrfs_dir_entry_debugprint(de);
                btrfs_dir_entry_free(de);
                break;
            }
            case BTRFS_ITEM_TYPE_EXTENT_DATA: {
                BTRFS_EXTENT_DATA *ed = btrfs_extent_data_fromraw(data, len);
                if (ed) {
                    btrfs_extent_data_debugprint(ed);
                    btrfs_extent_data_free(ed);
                } else {
                    btrfs_debug("error while deriving EXTENT_DATA item\n");
                }
                break;
            }
            case BTRFS_ITEM_TYPE_ROOT_ITEM: {
                BTRFS_ROOT_ITEM ri;
                btrfs_root_item_rawparse(data, &ri);
                btrfs_root_item_debugprint(&ri);
                break;
            }
            case BTRFS_ITEM_TYPE_EXTENT_ITEM:
            case BTRFS_ITEM_TYPE_METADATA_ITEM: {
                BTRFS_EXTENT_ITEM ei;
                btrfs_extent_item_rawparse(data, &ei);
                btrfs_extent_item_debugprint(&ei);
                break;
            }
            case BTRFS_ITEM_TYPE_DEV_ITEM: {
                BTRFS_DEV_ITEM di;
                btrfs_dev_item_rawparse(data, &di);
                btrfs_dev_item_debugprint(&di);
                break;
            }
            case BTRFS_ITEM_TYPE_CHUNK_ITEM:
                BTRFS_CHUNK_ITEM *ci = btrfs_chunk_item_fromraw(data);
                btrfs_chunk_item_debugprint(ci);
                btrfs_chunk_item_free(ci);
                break;
            }
        }

        btrfs_treenode_set_index(node, false, 1);
    }

    // if not leaf, recursively print subtrees
    if (node->header.level) {
        btrfs_treenode_set_index(node, true, 0);
        for (unsigned int i = 0; i < node->header.number_of_items; i++) {
            char text[128];
            snprintf(text, sizeof(text), "%s - subtree %d", a_description, node->index);
            btrfs_tree_dump(a_btrfs, node->kp.block_number, text);
            btrfs_treenode_set_index(node, false, 1);
        }
    }

    btrfs_treenode_free(node);
}
#endif



/*
 * open/close filesystem
 */


/**
 * Closes the Btrfs filesystem
 * @param a_fs FS info
 */
static void
btrfs_close(TSK_FS_INFO * a_fs)
{
    if (!a_fs)
        return;

    BTRFS_INFO *btrfs = (BTRFS_INFO*) a_fs;

    a_fs->tag = 0;

    // treenode cache
    tsk_deinit_lock(&btrfs->treenode_cache_lock);
    if (btrfs->treenode_cache_map) {
        for (btrfs_treenode_cache_map_t::iterator map_it = btrfs->treenode_cache_map->begin();
                map_it != btrfs->treenode_cache_map->end(); map_it++) {
            delete[] map_it->second;
        }
        delete btrfs->treenode_cache_map;
    }
    delete btrfs->treenode_cache_lru;

    delete btrfs->sb;
    delete btrfs->chunks;
    delete btrfs->subvolumes;
    delete btrfs->virt2real_inums;

    tsk_fs_free(a_fs);
}


#ifdef BTRFS_DEBUG
static TSK_WALK_RET_ENUM
btrfs_blockwalk_test_cb(const TSK_FS_BLOCK * a_block, void *a_ptr)
{
    // only print blocks which are not: raw and unalloced
    if (a_block->flags != (TSK_FS_BLOCK_FLAG_ENUM) (TSK_FS_BLOCK_FLAG_AONLY | TSK_FS_BLOCK_FLAG_RAW | TSK_FS_BLOCK_FLAG_UNALLOC))
        btrfs_debug("block 0x%016" PRIxDADDR ": 0x%03x\n", a_block->addr, a_block->flags);
    return TSK_WALK_CONT;
}


#if 0
static TSK_WALK_RET_ENUM
btrfs_inodewalk_test_cb(TSK_FS_FILE * a_file, void *a_ptr)
{
    btrfs_debug("inode %" PRIuINUM ": 0x%x\n", a_file->meta->addr, a_file->meta->flags);
    return TSK_WALK_CONT;
}
#endif
#endif


/**
 * Tries to open a Btrfs filesystem
 * @param img_info image info
 * @param offset byte offset within image
 * @param ftype FS type
 * @param pass - ignored
 * @return pointer to a Btrfs filesystem if no error occured, otherwise NULL
 */
TSK_FS_INFO *
btrfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
           TSK_FS_TYPE_ENUM ftype, [[maybe_unused]] const char *pass, uint8_t test)
{
    // clean up any error messages that are lying around
    tsk_error_reset();

    // check FS type
    if (!TSK_FS_TYPE_ISBTRFS(ftype)) {
        btrfs_error(TSK_ERR_FS_ARG, "Invalid FS Type in btrfs_open");
        return NULL;
    }


    // create struct (mem is zeroed!)
    BTRFS_INFO *btrfs = (BTRFS_INFO*) tsk_fs_malloc(sizeof(BTRFS_INFO));
    if (!btrfs)
        return NULL;

    // init struct
    TSK_FS_INFO *fs = &btrfs->fs_info;

    btrfs->test = test;
#ifdef BTRFS_DEBUG
    btrfs->test = 1;
#endif
    fs->img_info = img_info;
    fs->offset = offset;
    fs->ftype = ftype;
    fs->dev_bsize = fs->img_info->sector_size;

    fs->tag = TSK_FS_INFO_TAG;
    fs->endian = BTRFS_ENDIAN;
    fs->flags = TSK_FS_INFO_FLAG_HAVE_NANOSEC;
    fs->duname = "Block";

    fs->block_getflags = btrfs_block_getflags;
    fs->block_walk = btrfs_block_walk;

    fs->file_add_meta = btrfs_file_add_meta;
    fs->inode_walk = btrfs_inode_walk;

    fs->dir_open_meta = btrfs_dir_open_meta;
    fs->name_cmp = btrfs_name_cmp;

    fs->get_default_attr_type = btrfs_get_default_attr_type;
    fs->load_attrs = btrfs_load_attrs;

    fs->fsstat = btrfs_fsstat;
    fs->istat = btrfs_istat;

    fs->close = btrfs_close;

    // unimplemented functions
    fs->jblk_walk = btrfs_jblk_walk;
    fs->jentry_walk = btrfs_jentry_walk;
    fs->jopen = btrfs_jopen;
    fs->fscheck = btrfs_fscheck;


    // derive superblock
    if (!btrfs_superblock_search(btrfs)) {
        btrfs_error(TSK_ERR_FS_MAGIC, "No valid superblock found in btrfs_open");
        if (tsk_verbose)
            tsk_fprintf(stderr, "btrfs_open: No valid superblock found\n");
        tsk_fs_close(fs);
        return NULL;
    }
#ifdef BTRFS_DEBUG
    btrfs_superblock_debugprint(btrfs->sb);
#endif
    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_open: Found valid superblock having generation: %" PRId64 "\n",
                btrfs->sb->generation);


    // ensure we support all features
    uint64_t incompat_flags_unsupported =
            btrfs->sb->incompat_flags & ~BTRFS_SUPERBLOCK_INCOMPAT_FLAGS_SUPPORTED;
    if (incompat_flags_unsupported) {
        btrfs_debug("Unsupported superblock incompat_flags:\n");
#ifdef BTRFS_DEBUG
        btrfs_fsstat_print_incompat_flags(stdout, incompat_flags_unsupported);
#endif
        btrfs_error(TSK_ERR_FS_MAGIC, "Unsupported superblock incompat_flags: 0x%" PRIx64,
                incompat_flags_unsupported);
        if (tsk_verbose) {
            tsk_fprintf(stderr, "btrfs_open: Unsupported superblock incompat_flags:\n");
            btrfs_fsstat_print_incompat_flags(stderr, incompat_flags_unsupported);
        }
        tsk_fs_close(fs);
        return NULL;
    }

    fs->block_size = btrfs->sb->sectorsize;
    fs->block_count = btrfs->sb->dev_item.total_bytes / fs->block_size;
    fs->first_block = 0;
    fs->last_block = fs->block_count - 1;

    // prevent reading after image end in case of incomplete image
    // was: fs->last_block_act = MIN(fs->last_block, (fs->img_info->size - fs->offset) / fs->block_size - 1);
    fs->last_block_act = (fs->img_info->size - fs->offset) / fs->block_size - 1;
    if (fs->last_block_act > fs->last_block) {
        fs->last_block_act = fs->last_block;
    }

    fs->fs_id_used = sizeof(btrfs->sb->uuid);
    memcpy(fs->fs_id, btrfs->sb->uuid, fs->fs_id_used);


    // init treenode cache
    tsk_init_lock(&btrfs->treenode_cache_lock);
    btrfs->treenode_cache_map = new btrfs_treenode_cache_map_t;
    btrfs->treenode_cache_lru = new btrfs_treenode_cache_lru_t;


    // init physical <-> logical address mapping
    // step 1 - parse superblock system chunks for initial mapping
    btrfs->chunks = btrfs_chunks_from_superblock(btrfs);

    // step 2 - based on this, replace it with chunk tree mapping
    BTRFS_CACHED_CHUNK_MAPPING *old_chunks = btrfs->chunks;
    btrfs->chunks = btrfs_chunks_from_chunktree(btrfs);
    if (!btrfs->chunks) {
        tsk_error_errstr2_concat("- btrfs_open: parsing chunk tree");
        tsk_fs_close(fs);
        return NULL;
    }
    delete old_chunks;


    // init virtual <-> real inum mapping
    btrfs->subvolumes = new btrfs_subvolumes_t;
    btrfs->virt2real_inums = new btrfs_virt2real_inums_t;
    if (!btrfs_parse_subvolumes(btrfs)) {
        tsk_error_errstr2_concat("- btrfs_open: parsing all subvolumes");
        tsk_fs_close(fs);
        return NULL;
    }

    // set root inum (using FS_TREE instead of possible custom default subvol)
    if (!btrfs_inum_real2virt_map(btrfs, BTRFS_OBJID_FS_TREE, btrfs_subvol_root_inum(btrfs, BTRFS_OBJID_FS_TREE), &fs->root_inum)) {
        tsk_error_set_errstr2("btrfs_open: mapping root inum");
        tsk_fs_close(fs);
        return NULL;
    }

    fs->inum_count = btrfs->virt2real_inums->size() + BTRFS_VINUM_COUNT_SPECIAL;
    fs->first_inum = 0;
    fs->last_inum = fs->inum_count - 1;


    // derive extent tree root node address
    if (!btrfs_root_tree_derive_subtree_address(btrfs, BTRFS_OBJID_EXTENT_TREE, &btrfs->extent_tree_root_node_address)) {
        tsk_fs_close(fs);
        return NULL;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "btrfs_open: SB mirror: %d, node size: %ld block size: %d, blocks: %p virtual inodes: %lud subvols: %zd, label: '%s'\n",
                btrfs->sb_mirror_index, btrfs->sb->nodesize, fs->block_size, fs->block_count, fs->inum_count, btrfs->subvolumes->size(), btrfs->sb->label);


#ifdef BTRFS_DEBUG
    // debug parsing some trees
    btrfs_tree_dump(btrfs, btrfs->sb->root_tree_root, "root tree");
    btrfs_tree_dump(btrfs, btrfs->extent_tree_root_node_address, "extent tree");
    btrfs_tree_dump(btrfs, btrfs->sb->chunk_tree_root, "chunk tree");
    if (btrfs->sb->log_tree_root)
        btrfs_tree_dump(btrfs, btrfs->sb->log_tree_root, "log tree");

    uint64_t tmp_tree_root;

    btrfs_root_tree_derive_subtree_address(btrfs, 0x04, &tmp_tree_root);
    btrfs_tree_dump(btrfs, tmp_tree_root, "device tree");

    btrfs_root_tree_derive_subtree_address(btrfs, 0x07, &tmp_tree_root);
    btrfs_tree_dump(btrfs, tmp_tree_root, "checksum tree");


    // output subvolumes
    for (btrfs_subvolumes_t::iterator it = btrfs->subvolumes->begin(); it != btrfs->subvolumes->end(); it++) {
        char subtree_text[30];
        snprintf(subtree_text, sizeof(subtree_text), "subvolume 0x%" PRIx64, it->first);
        btrfs_tree_dump(btrfs, it->second.ri.root_node_block_number, it->first == BTRFS_OBJID_FS_TREE ? "FS tree" : subtree_text);
    }

    // output allocation flags of all blocks which are not: raw and unalloced
    btrfs_debug("##### blocks which are not: raw and unalloced #####\n");
    TSK_FS_BLOCK_WALK_FLAG_ENUM block_walk_test_flags = (TSK_FS_BLOCK_WALK_FLAG_ENUM) (TSK_FS_BLOCK_WALK_FLAG_ALLOC | TSK_FS_BLOCK_WALK_FLAG_UNALLOC | TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META | TSK_FS_BLOCK_WALK_FLAG_AONLY);
    tsk_fs_block_walk(fs, fs->first_block, fs->last_block, block_walk_test_flags, btrfs_blockwalk_test_cb, NULL);

#if 0
    // output meta flags of all inodes
    TSK_FS_META_FLAG_ENUM inode_walk_test_flags = (TSK_FS_META_FLAG_ENUM) (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC | TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
    tsk_fs_meta_walk(fs, fs->first_inum, fs->last_inum, inode_walk_test_flags, btrfs_inodewalk_test_cb, NULL);
#endif

    // inum mapping virt->real
    btrfs_debug("##### inum mapping virt->real #####\n");
    for (uint64_t vinum = 0; vinum < btrfs->virt2real_inums->size(); vinum++)
        btrfs_debug("%4" PRId64 " -> 0x%4" PRIx64 " 0x%4" PRIx64 "\n", vinum, (*btrfs->virt2real_inums)[vinum].first, (*btrfs->virt2real_inums)[vinum].second);

    // inum mapping real->virt
    btrfs_debug("##### inum mapping real->virt #####\n");
    for (btrfs_subvolumes_t::iterator it = btrfs->subvolumes->begin(); it != btrfs->subvolumes->end(); it++)
        for (btrfs_real2virt_inums_t::iterator ii = it->second.real2virt_inums.begin(); ii != it->second.real2virt_inums.end(); ii++)
            btrfs_debug("0x%4" PRIx64 " 0x%4" PRIx64 " -> %4" PRId64 "\n", it->first, ii->first, ii->second);
#endif

    return fs;
}
