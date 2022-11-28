# remove existing myserver and myclient instances
#rm myclient myserver

g++ -pthread -o myserver  mymailer/myserver.cpp -lldap -llber
g++ -o myclient  mymailer/myclient.cpp