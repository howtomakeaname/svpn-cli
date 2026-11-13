/* Test fixture only: a loopback CONNECT/echo peer using independent GmSSL.
 * Compile with the same algorithm definitions as the GmSSL static library;
 * TLS_CTX and TLS_CONNECT layouts depend on those definitions.
 * No production VPN ticket or external target is used by this fixture.
 */
#include <gmssl/tls.h>
#include <gmssl/error.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int send_all(TLS_CONNECT *c,const unsigned char *p,size_t len){while(len){size_t sent=0;if(tls_send(c,p,len,&sent)!=1||!sent)return -1;p+=sent;len-=sent;}return 1;}
int main(int argc,char **argv){
 if(argc!=4)return 2;
 signal(SIGPIPE,SIG_IGN);
 TLS_CTX ctx;
 int suite=atoi(argv[3]);
 if(tls_ctx_init(&ctx,TLS_protocol_tlcp,TLS_server_mode)!=1){fprintf(stderr,"ctx init failed\n");error_print();return 3;} if(tls_ctx_set_cipher_suites(&ctx,&suite,1)!=1){fprintf(stderr,"suite config failed\n");error_print();return 3;} if(tlcp_ctx_add_server_certificate_and_keys(&ctx,argv[1],argv[2],"temporary-interop-only")!=1){fprintf(stderr,"server certificate config failed\n");error_print();return 3;}
 int listener=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 if(bind(listener,(struct sockaddr*)&addr,sizeof(addr))||listen(listener,8))return 4;
 socklen_t size=sizeof(addr);getsockname(listener,(struct sockaddr*)&addr,&size);printf("%d\n",ntohs(addr.sin_port));fflush(stdout);
 for(int attempt=0;attempt<20;attempt++){
  int fd=accept(listener,NULL,NULL);if(fd<0)break;
  struct timeval timeout={5,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
  TLS_CONNECT conn;if(tls_init(&conn,&ctx)!=1||tls_set_socket(&conn,fd)!=1||tls_do_handshake(&conn)!=1){close(fd);continue;}
  unsigned char header[32769]={0},buf[16384];size_t total=0,len=0;int ok=1;
  while(!strstr((char*)header,"\r\n\r\n")){
   if(tls_recv(&conn,buf,sizeof(buf),&len)!=1||!len||total+len>32768){ok=0;break;}
   memcpy(header+total,buf,len);total+=len;
  }
  if(ok&&memcmp(header,"CONNECT ",8)==0){
   const char response[]="HTTP/1.1 200 Connection Established\r\n\r\nindependent-gmssl\n";
   if(send_all(&conn,(const unsigned char*)response,strlen(response))==1){
    while(tls_recv(&conn,buf,sizeof(buf),&len)==1&&len){if(send_all(&conn,buf,len)!=1)break;}
   }
  }
  tls_cleanup(&conn);shutdown(fd,SHUT_RDWR);close(fd);
 }
 close(listener);tls_ctx_cleanup(&ctx);return 0;
}
