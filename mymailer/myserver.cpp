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
#include <sys/wait.h>


#include <list>
#include <string.h>
#include <regex.h>
#include <dirent.h>

#include <sstream>
#include <fstream>


#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>

#include <ldap.h>





using namespace std;

/// default values /////////////////////////////////////////////////////////////////////////

#define BUF 1024
int port = 6543;
string mailspool = "spool";


/// lock in shared memory ///////////////////////////////////////////////////////////////////////

typedef struct
{
   pthread_mutex_t file_lock;
   pthread_mutex_t index_lock;
} shared_data;
static shared_data* locks = NULL;


/// ldap ///////////////////////////////////////////////////////////////////////

const char *ldapUri = "ldap://ldap.technikum-wien.at:389";
const int ldapVersion = LDAP_VERSION3;

///////////////////////////////////////////////////////////////////////////////

int abortRequested = 0;
int create_socket = -1;
int new_socket = -1;

///////////////////////////////////////////////////////////////////////////////

void *clientCommunication(void *data);
void signalHandler(int sig);
int nextIndex(string dir_path);

///////////////////////////////////////////////////////////////////////////////


//./twmailer-server <port> <mail-spool-directoryname>
int main(int argc, char *argv[])
{
   //setup
   if(argc < 3){
      printf("not enough args\n");
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


   // init locks
   // place our shared data in shared memory
   int prot = PROT_READ | PROT_WRITE;
   int flags = MAP_SHARED | MAP_ANONYMOUS;
   locks =(shared_data *) mmap(NULL, sizeof(shared_data), prot, flags, -1, 0);
   assert(locks);

   // initialise mutex so it works properly in shared memory
   pthread_mutexattr_t attr;
   pthread_mutexattr_init(&attr);
   pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
   pthread_mutex_init(&locks->index_lock, &attr);
   pthread_mutex_init(&locks->file_lock, &attr);

   
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
      if (( new_socket = accept(create_socket,
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

      //create child for every client connected and make them leave loop after that
      switch(fork())	{
         case -1: 
            printf("Child konnte nicht gestartet werden.");
            exit(EXIT_FAILURE);
            break;
         case 0:

            // START CLIENT
            // ignore printf error handling
            printf("Client connected from %s:%d...\n", inet_ntoa(cliaddress.sin_addr), ntohs(cliaddress.sin_port));

            //open up a new thread of clientCommunication and add it to the list of threads
            clientCommunication( &new_socket);

            new_socket = -1;
            break;
         default:
            break;
      }
   }

   //wait for every child process to exit
   while(wait(NULL) > 0) {}
   

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
   bool reset_values = false;

   bool logged_in = false; // TODO: ldap login
   int login_attempts = 0;
   string temp_uname = "";
   string temp_passw = "";

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

      /************************** LOGIN COMMAND *******************************/
      if(
         (strcasecmp(buffer, "LOGIN") == 0 || login_routine > 0)
         &&
         !(read_routine > 0 || list_routine > 0 || del_routine > 0 || send_routine > 0)
      ){

         printf("LOGIN:\n");
         if (login_routine == 0){
            printf("START\n");
            login_routine = 2;
         }else if (login_routine == 2){

            temp_uname  = buffer;
            printf("Username: %s\n",temp_uname.c_str());

            login_routine =1;
         }else if (login_routine == 1){

            temp_passw  = buffer;
            printf("Password: %s\n",temp_passw.c_str());

            //logic:

            // recv username
            char ldapBindUser[256];
            char rawLdapUser[128];

            strcpy(rawLdapUser,temp_uname.c_str()); //username received by function gets copied into ldapBindPassword to be compared

            sprintf(ldapBindUser, "uid=%s,ou=people,dc=technikum-wien,dc=at", rawLdapUser);
            printf("user set to: %s\n", ldapBindUser);

            char ldapBindPassword[256];

            if (login_attempts < 3){

               strcpy(ldapBindPassword,temp_passw.c_str()); //password received by function gets copied into ldapBindPassword to be compared

               // general
               int rc = 0; // return code
               ////////////////////////////////////////////////////////////////////////////
               // setup LDAP connection
               // https://linux.die.net/man/3/ldap_initialize
               LDAP *ldapHandle;
               rc = ldap_initialize(&ldapHandle, ldapUri);
               if (rc != LDAP_SUCCESS)
               {
                  fprintf(stderr, "ldap_init failed\n");
                  res = "ERR";
                  ++errorcode;
               }
               printf("connected to LDAP server %s\n", ldapUri);
               ////////////////////////////////////////////////////////////////////////////
               // set verison options
               // https://linux.die.net/man/3/ldap_set_option
               rc = ldap_set_option(
                  ldapHandle,
                  LDAP_OPT_PROTOCOL_VERSION, // OPTION
                  &ldapVersion);             // IN-Value
               if (rc != LDAP_OPT_SUCCESS)
               {
                  // https://www.openldap.org/software/man.cgi?query=ldap_err2string&sektion=3&apropos=0&manpath=OpenLDAP+2.4-Release
                  fprintf(stderr, "ldap_set_option(PROTOCOL_VERSION): %s\n", ldap_err2string(rc));
                  ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                  ++errorcode;
               }
               ////////////////////////////////////////////////////////////////////////////
               // start connection secure (initialize TLS)
               // https://linux.die.net/man/3/ldap_start_tls_s
               // int ldap_start_tls_s(LDAP *ld,
               //                      LDAPControl **serverctrls,
               //                      LDAPControl **clientctrls);
               // https://linux.die.net/man/3/ldap
               // https://docs.oracle.com/cd/E19957-01/817-6707/controls.html
               //    The LDAPv3, as documented in RFC 2251 - Lightweight Directory Access
               //    Protocol (v3) (http://www.faqs.org/rfcs/rfc2251.html), allows clients
               //    and servers to use controls as a mechanism for extending an LDAP
               //    operation. A control is a way to specify additional information as
               //    part of a request and a response. For example, a client can send a
               //    control to a server as part of a search request to indicate that the
               //    server should sort the search results before sending the results back
               //    to the client.
               rc = ldap_start_tls_s(
                  ldapHandle,
                  NULL,
                  NULL);
               if (rc != LDAP_SUCCESS)
               {
                  fprintf(stderr, "ldap_start_tls_s(): %s\n", ldap_err2string(rc));
                  ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                  ++errorcode;
               }
               ////////////////////////////////////////////////////////////////////////////
               // bind credentials
               // https://linux.die.net/man/3/lber-types
               // SASL (Simple Authentication and Security Layer)
               // https://linux.die.net/man/3/ldap_sasl_bind_s
               // int ldap_sasl_bind_s(
               //       LDAP *ld,
               //       const char *dn,
               //       const char *mechanism,
               //       struct berval *cred,
               //       LDAPControl *sctrls[],
               //       LDAPControl *cctrls[],
               //       struct berval **servercredp);

               BerValue bindCredentials;
               bindCredentials.bv_val = (char *)ldapBindPassword;
               bindCredentials.bv_len = strlen(ldapBindPassword);
               BerValue *servercredp; // server's credentials
               rc = ldap_sasl_bind_s(
                  ldapHandle,
                  ldapBindUser,
                  LDAP_SASL_SIMPLE,
                  &bindCredentials,
                  NULL,
                  NULL,
                  &servercredp);
               if (rc != LDAP_SUCCESS)
               {
                  fprintf(stderr, "LDAP bind error: %s\n", ldap_err2string(rc));
                  ldap_unbind_ext_s(ldapHandle, NULL, NULL);
                  ++errorcode;
               } else {
                  username = temp_uname;
                  logged_in = true;

                  res = "OK";

                  login_attempts = 0;
                  login_routine = 0;
               }



               //if (temp_passw.length() >= 4){
               //   username = temp_uname;
               //   logged_in = true;

               //   res = "OK";

               //   login_attempts = 0;
               //   login_routine = 0;
               //} else {
               //   printf("login failed\n");
               //   res = "ERR";
               //}

               login_attempts +=1;
            } else {
               printf("Error: too many login attempts. \n");
               ++errorcode;

               //reset variables
               temp_uname = "";
               temp_passw = "";
               login_routine = 0;
               login_attempts = 0;

            }
         }
      /************************** SEND COMMAND *******************************/
      }else if(
         (strcasecmp(buffer, "SEND") == 0 || send_routine > 0)
         &&
         !(read_routine > 0 || list_routine > 0 || del_routine > 0 || login_routine > 0)
      ){
         printf("SEND: \n");
         if (send_routine == 0)
         {
            //check login
            if (logged_in){
               printf("Logged in as \"%s\"\n",username.c_str());
            }else{
               errorcode += 1;
               printf("Error: Not logged in\n");
            }
            
            messege = std::stringstream();
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
               pthread_mutex_lock(&locks->file_lock);
               
               int mdc = mkdir(dir_path.str().c_str(), 0755);
               if(mdc == 0){
                  printf("Created new directory\n");
               }

               pthread_mutex_unlock(&locks->file_lock);

               //TODO: NEXTINDEX
               int index = nextIndex(dir_path.str());
               printf("Index: %d\n",index);

               std::stringstream file_path;
               file_path << dir_path.str() << "/" << index;

               
               pthread_mutex_lock(&locks->file_lock);

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

               pthread_mutex_unlock(&locks->file_lock);

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
         !(send_routine > 0 || list_routine > 0 || del_routine > 0 || login_routine > 0)
      ){
         printf("READ: \n");
         if (read_routine == 0)
         {
            printf("Start\n");
            //check login
            if (logged_in){
               printf("Logged in as \"%s\"\n",username.c_str());
            }else{
               errorcode += 1;
               printf("Error: Not logged in\n");
            }

            read_routine = 1;
         }else if (read_routine == 1)
         {
            msg_num = atoi(buffer);
            printf("ms_num: %d\n",msg_num);

            //logic:
            std::stringstream dir_path;
            dir_path << mailspool << "/" << username;
            printf("Dirpath: %s\n",dir_path.str().c_str());

            
            pthread_mutex_lock(&locks->file_lock);

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

         
            pthread_mutex_unlock(&locks->file_lock);


            //outcon
            read_routine = 0;
         }

      /************************** LIST COMMAND *******************************/
      }else if (
         (strcasecmp(buffer, "LIST") == 0 || list_routine > 0)
         &&
         !(read_routine > 0 || send_routine > 0 || del_routine > 0 || login_routine > 0)
      ){
         printf("LIST: \n");
         if (list_routine == 0)
         {
            //check login
            if (logged_in){
               printf("Logged in as \"%s\"\n",username.c_str());
            }else{
               errorcode += 1;
               printf("Error: Not logged in\n");
            }

            //logic:
            std::stringstream dir_path;
            dir_path << mailspool << "/" << username;
            printf("Dirpath: %s\n",dir_path.str().c_str());

            
            pthread_mutex_lock(&locks->file_lock);

            struct dirent *de;
            DIR *dr = opendir(dir_path.str().c_str());
            if(dr != NULL){
               std::stringstream results;

               int path_no = 0;
               while ((de = readdir(dr)) != NULL){
                  ++path_no;
                  if(path_no >= 3 && strcasecmp(de->d_name, "index.txt")!=0){
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
                  std::stringstream results_results;
                  results_results << path_no-2 << "\n";
                  results_results << results.str() << "\n";
               
                  printf("%s\n",results_results.str().c_str());
                  res = results_results.str();
               }else{
                  res = "0";
                  errorcode = 0;
                  printf("Error: Unknown!\n");

               }


               

               
               closedir(dr);
            }else{
               errorcode += 1;
               printf("Error: Dir \"%s\" does not exist.\n", dir_path.str().c_str());
            }

            
            pthread_mutex_unlock(&locks->file_lock);


            //outcon
            list_routine = 0;
         }




      /************************** DEL COMMAND *******************************/
      }else if (
         (strcasecmp(buffer, "DEL") == 0 || del_routine > 0)
         &&
         !(read_routine > 0 || list_routine > 0 || send_routine > 0 || login_routine > 0)
      ){
         printf("DEL: %d\n", del_routine);
         if (del_routine == 0)
         {
            printf("Start\n");
            //check login
            if (logged_in){
               printf("Logged in as \"%s\"\n",username.c_str());
            }else{
               errorcode += 1;
               printf("Error: Not logged in\n");
            }

            //entrypoint
            del_routine = 1;
         }else if (del_routine == 1)
         {
            msg_num = atoi(buffer);printf("ms_num: %d\n",msg_num);

            //logic:
            std::stringstream dir_path;
            dir_path << mailspool << "/" << username;
            printf("Dirpath: %s\n",dir_path.str().c_str());

            
            pthread_mutex_lock(&locks->file_lock);

            if(opendir(dir_path.str().c_str()) != NULL){
               std::stringstream file_path;
               std::stringstream return_message;

               file_path << dir_path.str() << "/" << msg_num;

               if (remove(file_path.str().c_str()) == 0){
                  printf("Deleted successfully");
               }
               else{
                  errorcode += 1;
                  printf("Unable to delete the file\n");
               }
            }else{
               errorcode += 1;
               printf("Error: dir \"%s\" does not exist.\n", dir_path.str().c_str());
            }

            
            pthread_mutex_unlock(&locks->file_lock);

            

            //outcon
            del_routine = 0;
         }




      }else if(strcasecmp(buffer, "quit") == 0){
         printf("Client is gonna quit btw \n");
         res = "OK";

         reset_values = true;
      }else{
         printf("this rout doesnt exist\n");
         res = "ERR";

         reset_values = true;

      }

      if(errorcode>0){
         printf("this input resulted in %d errors\n", errorcode);
         res = "ERR";
         
         reset_values = true;
      }

      if(reset_values){
         //reset routines
         send_routine = 0;
         read_routine = 0;
         list_routine = 0;
         del_routine = 0;

         //reset variables

         msg_num = 0;

         receiver = "";
         subject = "";
         messege = std::stringstream();

         
         errorcode = 0;
         
         reset_values = false;
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



int nextIndex(string dir_path){
   pthread_mutex_lock(&locks->index_lock);

   std::stringstream index_file;
   index_file << dir_path << "/index.txt";

   string temp_content = "";
   int outval = 0;
   ifstream ifs(index_file.str().c_str());
   if (ifs)
   {
      ifs >> temp_content;

      printf("%s\n", temp_content.c_str());
      outval = stoi(temp_content.c_str());
   }
   ifs.close();

   
   ofstream ofs(index_file.str().c_str());

   ofs << ++outval;
   ofs.close();

   
   pthread_mutex_unlock(&locks->index_lock);
   
   return outval;
}