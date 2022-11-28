# remove existing myserver and myclient instances
rm myclient myserver

g++ -o myserver  mymailer/myserver.cpp
g++ -o myclient  mymailer/myclient.cpp