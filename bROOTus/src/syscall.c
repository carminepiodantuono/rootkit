#include <linux/kernel.h>
#include <linux/module.h>

#include "kernel_variables.h"
#include "syscall.h"

int sys_call_table_pte_perm;

int set_addr_rw(unsigned long addr)
{
  unsigned int level;
  int result;

  // ottiene le entries della tabella delle pagine
  pte_t* pte = lookup_address(addr, &level);

  // salva i permessi
  result = pte->pte;

  // imposta i nuovi permessi
  pte->pte |= _PAGE_RW;

  return result;
}

// rispristina i permessi iniziali
void set_pte_permissions(unsigned long addr, int perm)
{
  unsigned int level;

  // ottiene le entries della pagina
  pte_t* pte = lookup_address(addr, &level);

  // imposta i nuovi permessi
  pte->pte = perm;
}

inline void syscall_table_modify_begin(void)
{
  sys_call_table_pte_perm = set_addr_rw((unsigned long) get_syscall_table_addr());
}

inline void syscall_table_modify_end(void)
{
  set_pte_permissions((unsigned long) get_syscall_table_addr(), sys_call_table_pte_perm);
}