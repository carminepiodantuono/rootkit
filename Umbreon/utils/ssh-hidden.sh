  
#include <stdio.h>
FILE *preload;

int main(int argc){
    if(preload = fopen("/etc/ld.so.preload","w")){
        fprintf(preload, "\n");
        fclose(preload);
        system("/bin/echo '[+] fixed'"); 
    // echo per sapere se si è fixato l'err
    }
    else printf("[-] shit\n");
}