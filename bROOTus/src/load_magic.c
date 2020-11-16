#include <linux/random.h>

#include "load_magic.h"

//indica se il modulo è ancora caricato -> usato epr verificare se ritorna il valore originale una volta deallocato il modulo
int MAGIC;
int magic_status;

void init_load_magic(void)
{
  // Setup the magic numbers
  get_random_bytes(&MAGIC, sizeof(MAGIC));
  magic_status = MAGIC;
}

void unset_magic(void)
{
  // Remove the magic from the loading state indicator
  magic_status = 0;
}

int check_load_magic(void)
{
  return MAGIC == magic_status;
}