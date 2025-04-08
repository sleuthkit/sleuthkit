#ifndef _TOOLS_UTIL_H
#define _TOOLS_UTIL_H

#include <memory>
#include <utility>

#include "tsk/base/tsk_base_i.h"

std::pair<
  std::unique_ptr<TSK_TCHAR*[], void(*)(TSK_TCHAR**)>,
  int
>
argv_to_tsk_tchar(int argc, char** argv);

#endif
