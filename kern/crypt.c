#include <extlib/include/tomcrypt_ext.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

unsigned char *kernmap1, *kernmap2;
off_t kernsize, hashsize = 0;

void
panic(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  abort();
}

void
openkern(const char *name) {
  int r, kernfd1, kernfd2;
  struct stat buf;
  char *new_name = "obj/kern/kernel_signed";
  if ((kernfd1 = open(name, O_RDWR | O_CREAT, 0666)) < 0)
    panic("open %s: %s", name, strerror(errno));
  if ((kernfd2 = open(new_name, O_RDWR | O_CREAT, 0666)) < 0)
    panic("open %s: %s", new_name, strerror(errno));
  if (fstat(kernfd1, &buf))
    panic("Bad call\n");
  kernsize = buf.st_size;
  if ((r = ftruncate(kernfd2, 0)) < 0 || (r = ftruncate(kernfd2, kernsize + hashsize)) < 0)
    panic("truncate %s: %s", new_name, strerror(errno));

  if ((kernmap1 = mmap(NULL, kernsize, PROT_READ | PROT_WRITE,
                      MAP_SHARED, kernfd1, 0)) == MAP_FAILED)
    panic("mmap %s: %s", name, strerror(errno));
  if ((kernmap2 = mmap(NULL, kernsize + hashsize, PROT_READ | PROT_WRITE,
                      MAP_SHARED, kernfd2, 0)) == MAP_FAILED)
    panic("mmap %s: %s", name, strerror(errno));
  close(kernfd1);
  close(kernfd2);
  memcpy(kernmap2 + hashsize, kernmap1, kernsize);
}

void 
signkern() {
  int hash_id = register_hash(&sha256_desc);
  unsigned char buf[32];
  unsigned long len = 32;
  if (hash_memory(hash_id, kernmap1, kernsize, buf, &len) != CRYPT_OK) {
    panic("hash_memory error\n");
  }
  for (int i = 0; i < sizeof(buf); ++i) {
    printf("%02x ", buf[i]);
  }
}


void
finishkern(void) {
  if ((msync(kernmap2, kernsize + hashsize, MS_SYNC)) < 0)
    panic("msync: %s", strerror(errno));
}



int main(void)
{
  char *name = "obj/kern/kernel";
  openkern(name);
  signkern();
  finishkern();
}
