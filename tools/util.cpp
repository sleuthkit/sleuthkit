#include "tools/util.h"

#include <cstdio>
#include <cstdlib>

std::pair<
  std::unique_ptr<TSK_TCHAR*[], void(*)(TSK_TCHAR**)>,
  int
>
argv_to_tsk_tchar(int argc, char** argv) {
#ifdef TSK_WIN32
  // On Windows, get the wide arguments (mingw doesn't support wmain)
  const auto args = std::unique_ptr<TSK_TCHAR*[]>, void(*)(TSK_TCHAR**)>{
    CommandLineToArgvW(GetCommandLineW(), &argc),
    [](TSK_TCHAR** v) { LocalFree(v); }
  };
  
  if (!args) {
    std::fprintf(stderr, "Error getting wide arguments\n");
    std::exit(1);
  }

  return { args, argc };
#else
  // Pass argv, argc through when not on Windows
  return {
    std::unique_ptr<TSK_TCHAR*[], void(*)(TSK_TCHAR**)>{
      argv,
      [](TSK_TCHAR**){}
    },
    argc
  };
#endif
}
