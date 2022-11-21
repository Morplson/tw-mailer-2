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
#include <dirent.h>

#include <sstream>
#include <fstream>

using namespace std;

///////////////////////////////////////////////////////////////////////////////

#define BUF 1024
int port = 6543;
string mailspool = "spool";




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
   mailspool = argv[2];


   printf("Port: %d\nMailspool: %s\n",port,mailspool.c_str());




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
   int login_routine = 0;

   //declare variables
   int errorcode = 0;
   string res = "OK"; // OK | ERR | <output>

   string username = "dummy"; // aka sender
   int msg_num = 0;

   string receiver;
   string subject;
   std::stringstream messege;


   //io file streams
   ofstream wf;
   ifstream rf;



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
      errorcode = 0;

      /************************** SEND COMMAND *******************************/
      if(
         (strcasecmp(buffer, "SEND") == 0 || send_routine > 0)
         &&
         !(read_routine > 0 || list_routine > 0 || del_routine > 0)
      ){
         printf("SEND: \n");
         printf("sr: %d\n",send_routine);
         if (send_routine == 0)
         {
            //entrypoint
            printf("Logged in as \"%s\"",username.c_str());

            send_routine = 3;
         }else if (send_routine == 3)
         {

            if(strlen(buffer) <= 8){
               receiver = buffer;
               printf("Receiver: %s\n",receiver.c_str());
            }else{
               errorcode +=1;
            }

            send_routine = 2;
         }else if (send_routine == 2)
         {
            if(strlen(buffer) <= 80){
               subject = buffer;
               printf("Subject: %s\n",subject.c_str());
            }else{
               errorcode +=1;
            }


            send_routine = 1;
         }else if (send_routine == 1)
         {
            if(strcmp(buffer, ".") == 0){
               std::stringstream dir_path;
               dir_path << mailspool << "/" << username;
               printf("Dirpath: %s\n",dir_path.str().c_str());

               //mkdir
               int mdc = mkdir(dir_path.str().c_str(), 0755);
               if(mdc == 0){
                  printf("Created new directory\n");
               }

               //TODO: NEXTINDEX
               int index = 0;

               std::stringstream file_path;
               file_path << dir_path.str() << "/" << index;

               wf.open(file_path.str().c_str());


               wf << "Sender: " << username << "\n";
               printf("Sender: \n%s\n", username.c_str());
               wf << "Receiver: " << receiver << "\n";
               printf("Receiver: \n%s\n", receiver.c_str());
               wf << "Subject: " << subject << "\n";
               printf("Subject: \n%s\n", subject.c_str());
               wf << "Message: " << messege.str() << "\n";
               printf("Message:\n%s\n", messege.str().c_str());

               wf.close();

               send_routine = 0;
            }else
            {
               char *tm = buffer;
               messege << tm << "\n";

               printf("Msg:\n************\n %s\n************\n", messege.str().c_str());

            }
         }
      /************************** READ COMMAND *******************************/
      }else if (
         (strcasecmp(buffer, "READ") == 0 || read_routine > 0)
         &&
         !(send_routine > 0 || list_routine > 0 || del_routine > 0)
      ){
         printf("READ: \n");
         if (read_routine == 0)
         {
            printf("Start\n");

            read_routine = 1;
         }else if (read_routine == 1)
         {
            msg_num = atoi(buffer);
            printf("ms_num: %d\n",msg_num);

            //logic:
            std::stringstream dir_path;
            dir_path << mailspool << "/" << username;
            printf("Dirpath: %s\n",dir_path.str().c_str());

            if(opendir(dir_path.str().c_str()) != NULL){
               std::stringstream file_path;
               std::stringstream return_message;

               file_path << dir_path.str() << "/" << msg_num;

               rf.open(file_path.str().c_str());

               string temp;
               if (rf.is_open() )
               {
                  return_message << rf.rdbuf();

                  rf.close();

                  res = return_message.str();
               }else{
                  errorcode += 1;
                  printf("Error: File not found!\n");
               }
            }else{
               errorcode += 1;
               printf("Error: dir \"%s\" does not exist.\n", dir_path.str().c_str());
            }


            //outcon
            read_routine = 0;
         }

      /************************** LIST COMMAND *******************************/
      }else if (
         (strcasecmp(buffer, "LIST") == 0 || list_routine > 0)
         &&
         !(read_routine > 0 || send_routine > 0 || del_routine > 0)
      ){
         printf("LIST: \n");
         if (list_routine == 0)
         {
            //logic:
            std::stringstream dir_path;
            dir_path << mailspool << "/" << username;
            printf("Dirpath: %s\n",dir_path.str().c_str());

            struct dirent *de;
            DIR *dr = opendir(dir_path.str().c_str());
            if(dr != NULL){
               std::stringstream results;

               int path_no = 0;
               while ((de = readdir(dr)) != NULL){
                  ++path_no;
                  if(path_no >= 3){
                     std::stringstream file_path;
                     file_path << dir_path.str() << "/" << de->d_name;
                     printf("file_path: %s\n",file_path.str().c_str());

                     rf.open(file_path.str().c_str());

                     if(rf.is_open()){

                        //Get the subject from line 3
                        string subject_line = "";
                        int line_no = 0;
                        while (line_no != 3 && getline(rf, subject_line)) {
                           ++line_no;
                        }

                        if (line_no == 3) {
                           results << de->d_name << ": " << subject_line << "\n";
                        } else {
                           // The file contains fewer than two lines.
                           errorcode += 1;
                           printf("Error: File contains less than 3 lines.\n");
                        }

                        rf.close();
                     }
                  }   
               }


               if(!results.str().empty()) {
                  printf("%s\n",results.str().c_str());
                  res = results.str();
               }else{
                  errorcode += 1;
                  printf("Error: Unknown!\n");

               }


               

               
               closedir(dr);
            }else{
               errorcode += 1;
               printf("Error: Dir \"%s\" does not exist.\n", dir_path.str().c_str());
            }


            //outcon
            list_routine = 0;
         }




      /************************** DEL COMMAND *******************************/
      }else if (
         (strcasecmp(buffer, "DEL") == 0 || del_routine > 0)
         &&
         !(read_routine > 0 || list_routine > 0 || send_routine > 0)
      ){
         printf("DEL: %d\n", del_routine);
         if (del_routine == 0)
         {
            printf("Start\n");

            //entrypoint
            del_routine = 1;
         }else if (del_routine == 1)
         {
            msg_num = atoi(buffer);printf("ms_num: %d\n",msg_num);

            //logic:
            std::stringstream dir_path;
            dir_path << mailspool << "/" << username;
            printf("Dirpath: %s\n",dir_path.str().c_str());

            if(opendir(dir_path.str().c_str()) != NULL){
               std::stringstream file_path;
               std::stringstream return_message;

               file_path << dir_path.str() << "/" << msg_num;

               if (remove(file_path.str().c_str()) == 0){
                  printf("Deleted successfully");
               }
               else{
                  errorcode += 1;
                  printf("Unable to delete the file");
               }
            }else{
               errorcode += 1;
               printf("Error: dir \"%s\" does not exist.\n", dir_path.str().c_str());
            }

            

            //outcon
            del_routine = 0;
         }




      }else
      {
         printf("no path \n");

         //declare routines
         send_routine = 0;
         read_routine = 0;
         list_routine = 0;
         del_routine = 0;

         //declare variables
         res = "404";

         msg_num = 0;

         receiver = "";
         subject = "";
         messege = std::stringstream();

         errorcode = 0;
      }


      if(errorcode>0){
         //declare routines
         send_routine = 0;
         read_routine = 0;
         list_routine = 0;
         del_routine = 0;

         //declare variables
         res = "ERR";

         msg_num = 0;

         receiver = "";
         subject = "";
         messege = std::stringstream();

         printf("this input resulted in %d errors\n", errorcode);
         errorcode = 0;
      }









      //bzero(buffer, BUF);

      if(res.length()>0){
         if (send(*current_socket, res.c_str() , strlen(res.c_str()), 0) == -1)
         {
            perror("send answer failed");
            return NULL;
         }

         printf("\n");
      }




   } while (strcasecmp(buffer, "QUIT") != 0 && !abortRequested);

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
