
#include "fs.h"
#include <tomcrypt.h>

unsigned char passwd[256];

unsigned char diskkey[64];

unsigned char tmp_page[BLKSIZE];

symmetric_xts xts;

// Return the virtual address of this disk block.
void *
diskaddr(uint32_t blockno) {
  if (blockno == 0 || (super && blockno >= super->s_nblocks))
    panic("bad block number %08x in diskaddr", blockno);
  void *r = (void *)(uintptr_t)(DISKMAP + blockno * BLKSIZE);
#ifdef SANITIZE_USER_SHADOW_BASE
  platform_asan_unpoison(r, BLKSIZE);
#endif
  return r;
}

// Is this virtual address mapped?
bool
va_is_mapped(void *va) {
  return ((uvpml4e[PML4(va)] & PTE_P) && (uvpde[VPDPE(va)] & PTE_P) &&
          (uvpd[VPD(va)] & PTE_P) && (uvpt[PGNUM(va)] & PTE_P));
}

// Is this virtual address dirty?
bool
va_is_dirty(void *va) {
  return (uvpt[PGNUM(va)] & PTE_D) != 0;
}

// Fault any disk block that is read in to memory by
// loading it from disk.
static void
bc_pgfault(struct UTrapframe *utf) {
  void *addr        = (void *)utf->utf_fault_va;
  uint32_t blockno  = (uint32_t)((uintptr_t)addr - (uintptr_t)DISKMAP) / BLKSIZE;
  uint64_t tweak[2] = {blockno, 0}; 

  // Check that the fault was within the block cache region
  if (addr < (void *)DISKMAP || addr >= (void *)(DISKMAP + DISKSIZE))
    panic("page fault in FS: eip %p, va %p, err %04lx",
          (void *)utf->utf_rip, addr, (unsigned long)utf->utf_err);

  // Sanity check the block number.
  if (super && blockno >= super->s_nblocks)
    panic("reading non-existent block %08x out of %08x\n", blockno, super->s_nblocks);

  // Allocate a page in the disk map region, read the contents
  // of the block from the disk into that page.
  // Hint: first round addr to page boundary. fs/ide.c has code to read
  // the disk.
  //
  // LAB 10: Your code here.
  addr = ROUNDDOWN(addr, PGSIZE);
  int r = sys_page_alloc(0, addr, PTE_W);
	if (r < 0) {
		panic("sys_page_alloc: %i", r);
  }
  r = ide_read(blockno * BLKSECTS, tmp_page, BLKSECTS);
	if (r < 0) {
		panic("ide_read: %i", r);
  }
  r = xts_decrypt(tmp_page, BLKSIZE, addr, (unsigned char *)&tweak, &xts);
  if (r != CRYPT_OK) {
    panic("unable to decrypt block no: %d, addr: %p", blockno, addr);
  }
  r = sys_page_map(0, addr, 0, addr, uvpt[PGNUM(addr)] & PTE_SYSCALL);
	if (r < 0) {
		panic("sys_page_map: %i", r);
  }
	if (bitmap && block_is_free(blockno)) {
		panic("reading free block %08x\n", blockno);
  }
}

// Flush the contents of the block containing VA out to disk if
// necessary, then clear the PTE_D bit using sys_page_map.
// If the block is not in the block cache or is not dirty, does
// nothing.
// Hint: Use va_is_mapped, va_is_dirty, and ide_write.
// Hint: Use the PTE_SYSCALL constant when calling sys_page_map.
// Hint: Don't forget to round addr down.
void
flush_block(void *addr) {
  uint32_t blockno = (uint32_t)((uintptr_t)addr - (uintptr_t)DISKMAP) / BLKSIZE;
  uint64_t tweak[2] = {blockno, 0}; 

  if (addr < (void *)(uintptr_t)DISKMAP || addr >= (void *)(uintptr_t)(DISKMAP + DISKSIZE))
    panic("flush_block of bad va %p", addr);
  if (super && blockno >= super->s_nblocks)
    panic("reading non-existent block %08x out of %08x\n", blockno, super->s_nblocks);

  // LAB 10: Your code here.
  addr = ROUNDDOWN(addr, PGSIZE);
	if (!va_is_mapped(addr) || !va_is_dirty(addr)) {
		return;
  }

  int r = xts_encrypt(addr, BLKSIZE, tmp_page, (unsigned char *)&tweak, &xts);
  if (r != CRYPT_OK) {
    panic("unable to encrypt block no: %d, addr: %p", blockno, addr);
  }

  r = ide_write(blockno * BLKSECTS, tmp_page, BLKSECTS);
  if (r < 0) {
		panic("ide_write: %i", r);
  }
  r = sys_page_map(0, addr, 0, addr, uvpt[PGNUM(addr)] & PTE_SYSCALL);
	if (r < 0) {
		panic("sys_page_map: %i", r);
  }
}

// Test that the block cache works, by smashing the superblock and
// reading it back.
static void
check_bc(void) {
  struct Super backup;

  // back up super block
  memmove(&backup, diskaddr(1), sizeof backup);

  // smash it
  strcpy(diskaddr(1), "OOPS!\n");
  flush_block(diskaddr(1));
  assert(va_is_mapped(diskaddr(1)));
  assert(!va_is_dirty(diskaddr(1)));

  // clear it out
  sys_page_unmap(0, diskaddr(1));
  assert(!va_is_mapped(diskaddr(1)));

  // read it back in
  assert(strcmp(diskaddr(1), "OOPS!\n") == 0);

  // fix it
  memmove(diskaddr(1), &backup, sizeof backup);
  flush_block(diskaddr(1));

  cprintf("block cache is good\n");
}

void
key_init() {
  if (sys_get_disk_passwd(passwd) != 0) {
    panic("Unable to get gisk password");
  }
  unsigned char salt[] = "OMGThisisJOSAAAABKjhkas";
  unsigned char info[] = "OK, This is JOS disk encryption.";
  int hash_id = register_hash(&sha256_desc);

  hkdf(hash_id, salt, sizeof(salt), info, sizeof(info), passwd, sizeof(passwd), diskkey, sizeof(diskkey));

  memset(passwd, 0, sizeof(passwd));

  int32_t cipher_id = register_cipher(&aes_desc);
  if (cipher_id != CRYPT_OK) {
    panic("Unable to register cipher");
  }
  int32_t res = xts_start(cipher_id, diskkey, diskkey + sizeof(diskkey)/2, sizeof(diskkey)/2, 0, &xts);
  if (res != CRYPT_OK) {
    panic("Unable to initialize cipher");
  }
}

void
bc_init(void) {
  struct Super super;

  key_init();
  set_pgfault_handler(bc_pgfault);
  check_bc();
  
  // cache the super block by reading it once
  memmove(&super, diskaddr(1), sizeof super);
}
