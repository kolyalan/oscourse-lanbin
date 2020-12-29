
#include <inc/lib.h>

void
exit(int status) {
  close_all();
  sys_env_destroy(0);
}

void abort(void) {
  exit(0);
}