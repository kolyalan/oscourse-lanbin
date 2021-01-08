#include <extlib/include/tomcrypt_ext.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

unsigned char *kernmap1;
off_t kernsize, keysize, hashsize = 32;

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
  int kernfd1;
  struct stat buf;
  if ((kernfd1 = open(name, O_RDWR | O_CREAT, 0666)) < 0)
    panic("open %s: %s", name, strerror(errno));
  if (fstat(kernfd1, &buf))
    panic("Bad call\n");
  kernsize = buf.st_size;

  if ((kernmap1 = mmap(NULL, kernsize, PROT_READ | PROT_WRITE,
                      MAP_SHARED, kernfd1, 0)) == MAP_FAILED)
    panic("mmap %s: %s", name, strerror(errno));
  close(kernfd1);
}

void 
signkern() {
  int hash_id = register_hash(&sha256_desc);
  unsigned char buf[hashsize];
  unsigned long len = hashsize;
  if (hash_memory(hash_id, kernmap1, kernsize, buf, &len) != CRYPT_OK) {
    panic("hash_memory error\n");
  }

  FILE *out = fopen("LoaderPkg/Loader/hash.c", "w");
  fprintf(out, "UINT8 Hash[32]={");
  for (int i = 0; i < sizeof(buf); ++i) {
    fprintf(out, "0x%02x, ", buf[i]);
  }
  fprintf(out, "};\n");

}


int main(void)
{
  char *name = "obj/kern/kernel";
  openkern(name);
  signkern();
}
