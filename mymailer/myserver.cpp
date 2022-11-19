#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <sys/stat.h>

#include <list>
#include <string.h>
#include <regex.h>

#include <sstream>

using namespace std;  

///////////////////////////////////////////////////////////////////////////////

#define BUF 1024
int port = 6543;
char* mailspool;


///////////////////////////////////////////////////////////////////////////////

int abortRequested = 0;
int create_socket = -1;
int new_socket = -1;

///////////////////////////////////////////////////////////////////////////////

void *clientCommunication(void *data);
void signalHandler(int sig);

///////////////////////////////////////////////////////////////////////////////


//./twmailer-server <port> <mail-spool-directoryname>
int main(int argc, char *argv[])
{
   //setup
   if(argc < 3){
      perror("not enough args");
      return EXIT_FAILURE;
   }

   int port = atoi(argv[1]);
   char* mailspool = argv[2];

   chdir(mailspool);

   printf("Port: %d\nMailspool: %s\n",port,mailspool);




   socklen_t addrlen;
   struct sockaddr_in address, cliaddress;
   int reuseValue = 1;

   ////////////////////////////////////////////////////////////////////////////
   // SIGNAL HANDLER
   // SIGINT (Interrup: ctrl+c)
   // https://man7.org/linux/man-pages/man2/signal.2.html
   if (signal(SIGINT, signalHandler) == SIG_ERR)
   {
      perror("signal can not be registered");
      return EXIT_FAILURE;
   }

   ////////////////////////////////////////////////////////////////////////////
   // CREATE A SOCKET
   // https://man7.org/linux/man-pages/man2/socket.2.html
   // https://man7.org/linux/man-pages/man7/ip.7.html
   // https://man7.org/linux/man-pages/man7/tcp.7.html
   // IPv4, TCP (connection oriented), IP (same as client)
   if ((create_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
   {
      perror("Socket error"); // errno set by socket()
      return EXIT_FAILURE;
   }

   ////////////////////////////////////////////////////////////////////////////
   // SET SOCKET OPTIONS
   // https://man7.org/linux/man-pages/man2/setsockopt.2.html
   // https://man7.org/linux/man-pages/man7/socket.7.html
   // socket, level, optname, optvalue, optlen
   if (setsockopt(create_socket,
                  SOL_SOCKET,
                  SO_REUSEADDR,
                  &reuseValue,
                  sizeof(reuseValue)) == -1)
   {
      perror("set socket options - reuseAddr");
      return EXIT_FAILURE;
   }

   if (setsockopt(create_socket,
                  SOL_SOCKET,
                  SO_REUSEPORT,
                  &reuseValue,
                  sizeof(reuseValue)) == -1)
   {
      perror("set socket options - reusePort");
      return EXIT_FAILURE;
   }

   ////////////////////////////////////////////////////////////////////////////
   // INIT ADDRESS
   // Attention: network byte order => big endian
   memset(&address, 0, sizeof(address));
   address.sin_family = AF_INET;
   address.sin_addr.s_addr = INADDR_ANY;
   address.sin_port = htons(port);

   ////////////////////////////////////////////////////////////////////////////
   // ASSIGN AN ADDRESS WITH PORT TO SOCKET
   if (bind(create_socket, (struct sockaddr *)&address, sizeof(address)) == -1)
   {
      perror("bind error");
      return EXIT_FAILURE;
   }

   ////////////////////////////////////////////////////////////////////////////
   // ALLOW CONNECTION ESTABLISHING
   // Socket, Backlog (= count of waiting connections allowed)
   if (listen(create_socket, 5) == -1)
   {
      perror("listen error");
      return EXIT_FAILURE;
   }

   while (!abortRequested)
   {
      /////////////////////////////////////////////////////////////////////////
      // ignore errors here... because only information message
      // https://linux.die.net/man/3/printf
      printf("Waiting for connections...\n");

      /////////////////////////////////////////////////////////////////////////
      // ACCEPTS CONNECTION SETUP
      // blocking, might have an accept-error on ctrl+c
      addrlen = sizeof(struct sockaddr_in);
      if ((new_socket = accept(create_socket,
                               (struct sockaddr *)&cliaddress,
                               &addrlen)) == -1)
      {
         if (abortRequested)
         {
            perror("accept error after aborted");
         }
         else
         {
            perror("accept error");
         }
         break;
      }

      /////////////////////////////////////////////////////////////////////////
      // START CLIENT
      // ignore printf error handling
      printf("Client connected from %s:%d...\n",
             inet_ntoa(cliaddress.sin_addr),
             ntohs(cliaddress.sin_port));
      clientCommunication(&new_socket); // returnValue can be ignored
      new_socket = -1;
   }

   // frees the descriptor
   if (create_socket != -1)
   {
      if (shutdown(create_socket, SHUT_RDWR) == -1)
      {
         perror("shutdown create_socket");
      }
      if (close(create_socket) == -1)
      {
         perror("close create_socket");
      }
      create_socket = -1;
   }

   return EXIT_SUCCESS;
}





int compliesWithRegex(char* input)
{
   regex_t regex;
   int reti;

   /* Compile regular expression */
   reti = regcomp(&regex, "^[a-z0-9]{1,10}$", 0);
   if (reti) {
      printf("Could not compile regex\n");
      return 0;
      //exit(1);
   }

   /* Execute regular expression */
   reti = regexec(&regex, input, 0, NULL, 0);
   if (!reti) {
      return 1;
   }
   else {
      //regerror(reti, &regex, input, sizeof(input));
      //printf("Regex match failed: %s\n", input);
      return 0;
   }
}






void *clientCommunication(void *data)
{
   char buffer[BUF];
   int size;
   int *current_socket = (int *)data;

   ////////////////////////////////////////////////////////////////////////////
   // SEND welcome message
   strcpy(buffer, "Welcome to myserver!\r\nPlease enter your commands...\r\n");
   if (send(*current_socket, buffer, strlen(buffer), 0) == -1)
   {
      perror("send failed");
      return NULL;
   }



   //declare routines
   int send_routine = 0;
   int read_routine = 0;
   int list_routine = 0;
   int del_routine = 0;

   //declare variables
   int errorcode = 0;	
   string res = "OK"; // OK | ERR | <output>

   string username;
   int msg_num = 0;

   string sender;
   string reciever;
   string subject;
   std::stringstream messege;


   do
   {
      /////////////////////////////////////////////////////////////////////////
      // RECEIVE
      size = recv(*current_socket, buffer, BUF - 1, 0);
      if (size == -1)
      {
         if (abortRequested)
         {
            perror("recv error after aborted");
         }
         else
         {
            perror("recv error");
         }
         break;
      }

      if (size == 0)
      {
         printf("Client closed remote socket\n"); // ignore error
         break;
      }

      // remove ugly debug message, because of the sent newline of client
      if (buffer[size - 2] == '\r' && buffer[size - 1] == '\n')
      {
         size -= 2;
      }
      else if (buffer[size - 1] == '\n')
      {
         --size;
      }

      buffer[size] = '\0';
      printf("Message received: %s\n", buffer); // ignore error

   	
      ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
      //////////////////////////////////////////////// MAILOPTIONS ///////////////////////////////////////////////////////
      ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


      res = "OK";

      if(strcmp(buffer, "SEND") == 0 || send_routine > 0){ 
         printf("Entered SEND path: \n");
         if (send_routine == 0)
         {
            printf("Start\n");

            send_routine = 4;
         }else if (send_routine = 4)
         {
            if(compliesWithRegex(buffer) != 0){
               sender = buffer;
            }else{
               errorcode +=1;
            }
            

            send_routine = 3;
         }else if (send_routine = 3)
         {

            if(compliesWithRegex(buffer) != 0){
               reciever = buffer;
            }else{
               errorcode +=1;
            }

            send_routine = 2;
         }else if (send_routine = 2)
         {
            subject = buffer;


            send_routine = 1;
         }else if (send_routine = 1)
         {
            if(strcmp(buffer, ".") == 0){
               std::stringstream dir_path;
               dir_path << mailspool << "/" << sender;

               //mkdir
               int mdc = mkdir(dir_path.str().c_str(), 0755);
               if(mdc == 0){
                  printf("Created new directory");
               }

               //TODO: NEXTINDEX
               int index = 0;

               std::stringstream file_path;
               file_path << dir_path.str() << "/" << index;


               send_routine = 0;
            }else
            {
               char *tm = buffer;
               messege << tm;
            }
            
         }
         
         
         
         
                
         
      }else if (strcmp(buffer, "READ") == 0 || read_routine > 0)
      {
         printf("Entered READ path: \n");
         if (read_routine == 0)
         {
            printf("Start\n");

            read_routine = 2;
         }else if(read_routine == 2){
            
            username = buffer;

            printf("Username: %s\n",username.c_str());

            //next is 1
            read_routine = 1;
         }else if (read_routine == 1)
         {
            msg_num = atoi(buffer);
            printf("MSG: %d\n",msg_num);

            //remove halts for some reason??
            //TODO: fix
            //system("cat");

            //outcon
            read_routine = 0;
         }

      }else if (strcmp(buffer, "LIST") == 0 || list_routine > 0)
      {
         printf("Entered LIST path: \n");
         if (list_routine == 0)
         {
            printf("Start\n");

            list_routine = 1;
         }else if(list_routine = 1)
         {
            username = buffer;

            printf("Username: %s\n",username.c_str());

            /* TODO: code */
            //system("ls");

            //outcon
            list_routine = 0;
         }
         



      }else if (strcmp(buffer, "DEL") == 0 || del_routine > 0)
      {
         printf("Entered DEL path: %d\n", del_routine);
         if (del_routine == 0)
         {
            printf("Start\n");

            //entrypoint
            del_routine = 2;
         }else if(del_routine == 2){
            
            username = buffer;

            printf("Username: %s\n",username.c_str());


            //next is 1
            del_routine = 1;
         }else if (del_routine == 1)
         {
            int errcon = 0;
            msg_num = atoi(buffer);
            printf("MSG: %d\n",msg_num);

            //remove halts for some reason??
            //TODO: fix
            //remove(strcat(username, buffer));

            //system("rm")

            //outcon
            del_routine = 0;
         }
         
         


      }else
      {
         printf("Entered no :( path: \n");

         //declare routines
         send_routine = 0;
         read_routine = 0;
         list_routine = 0;
         del_routine = 0;

         //declare variables
         res = "OK";

         username = "";
         msg_num = 0;

         sender = "";
         reciever = "";
         subject = "";
         messege = std::stringstream();
      }
      
      
      if(errorcode>0){
         //declare routines
         send_routine = 0;
         read_routine = 0;
         list_routine = 0;
         del_routine = 0;

         //declare variables
         res = "ERR";

         username = "";
         msg_num = 0;

         sender = "";
         reciever = "";
         subject = "";
         messege = std::stringstream();
      }
      
      






      
      //bzero(buffer, BUF);


      if (send(*current_socket, res.c_str() , strlen(res.c_str()), 0) == -1)
      {
         perror("send answer failed");
         return NULL;
      }


   } while (strcmp(buffer, "QUIT") != 0 && !abortRequested);

   // closes/frees the descriptor if not already
   if (*current_socket != -1)
   {
      if (shutdown(*current_socket, SHUT_RDWR) == -1)
      {
         perror("shutdown new_socket");
      }
      if (close(*current_socket) == -1)
      {
         perror("close new_socket");
      }
      *current_socket = -1;
   }

   return NULL;
}





void signalHandler(int sig)
{
   if (sig == SIGINT)
   {
      printf("abort Requested... "); // ignore error
      abortRequested = 1;
      /////////////////////////////////////////////////////////////////////////
      // With shutdown() one can initiate normal TCP close sequence ignoring
      // the reference count.
      // https://beej.us/guide/bgnet/html/#close-and-shutdownget-outta-my-face
      // https://linux.die.net/man/3/shutdown
      if (new_socket != -1)
      {
         if (shutdown(new_socket, SHUT_RDWR) == -1)
         {
            perror("shutdown new_socket");
         }
         if (close(new_socket) == -1)
         {
            perror("close new_socket");
         }
         new_socket = -1;
      }

      if (create_socket != -1)
      {
         if (shutdown(create_socket, SHUT_RDWR) == -1)
         {
            perror("shutdown create_socket");
         }
         if (close(create_socket) == -1)
         {
            perror("close create_socket");
         }
         create_socket = -1;
      }
   }
   else
   {
      exit(sig);
   }
}
