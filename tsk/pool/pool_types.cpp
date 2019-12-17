#include "tsk_pool.h"

#include <string>

/**
 * \internal
 */
struct POOL_TYPES {
  std::string name;
  TSK_POOL_TYPE_ENUM code;
  std::string comment;
};

static const POOL_TYPES pool_type_table[]{
    {"auto", TSK_POOL_TYPE_DETECT, "auto-detect"},
    {"apfs", TSK_POOL_TYPE_APFS, "APFS container"},
};

/**
 * \ingroup vslib
 * Parse a string with the pool container type and return its internal ID.
 *
 * @param str String to parse.
 * @returns ID of string (or unsupported if the name is unknown)
 */
TSK_POOL_TYPE_ENUM
tsk_pool_type_toid(const TSK_TCHAR *str) {
  char tmp[16];
  int i;

  // convert to char
  for (i = 0; i < 15 && str[i] != '\0'; i++) {
    tmp[i] = (char)str[i];
  }
  tmp[i] = '\0';

  return tsk_pool_type_toid_utf8(tmp);
}

/**
 * \ingroup poollib
 * Parse a string with the pool container type and return its internal ID.
 *
 * @param str String to parse, always UTF-8.
 * @returns ID of string (or unsupported if the name is unknown)
 */
TSK_POOL_TYPE_ENUM
tsk_pool_type_toid_utf8(const char *str) {
  for (const auto &type : pool_type_table) {
    if (type.name == str) {
      return type.code;
    }
  }

  return TSK_POOL_TYPE_UNSUPP;
}

/**
 * \ingroup poollib
 * Print the supported pool container types to a file handle
 * @param hFile File handle to print to
 */
void tsk_pool_type_print(FILE *hFile) {
  tsk_fprintf(hFile, "Supported file system types:\n");

  for (const auto &type : pool_type_table) {
    tsk_fprintf(hFile, "\t%s (%s)\n", type.name.c_str(), type.comment.c_str());
  }
}

/**
 * \ingroup poollib
 * Return the string name of a pool container type id.
 * @param ftype Pool container type id
 * @returns Name or NULL on error
 */
const char *tsk_pool_type_toname(TSK_POOL_TYPE_ENUM ptype) {
  for (const auto &type : pool_type_table) {
    if (type.code == ptype) {
      return type.name.c_str();
    }
  }

  return nullptr;
}

/**
 * \ingroup poollib
 * Return the supported pool container types.
 * @returns The bit in the return value is 1 if the type is supported.
 */
TSK_POOL_TYPE_ENUM
tsk_fs_type_supported() {
  TSK_POOL_TYPE_ENUM sup_types{};

  for (const auto &type : pool_type_table) {
    sup_types = static_cast<TSK_POOL_TYPE_ENUM>(sup_types | type.code);
  }

  return sup_types;
}
