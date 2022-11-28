# remove existing myserver and myclient instances
#rm myclient myserver

g++ -pthread -o myserver  mymailer/myserver.cpp
g++ -o myclient  mymailer/myclient.cpp