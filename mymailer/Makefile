COMPILER = g++
CFLAGS = -Wall -Wextra

tclient: myclient.cpp
	${COMPILER} ${CFLAGS} -o tclient myclient.cpp -std=c++17

tserver: myserver.cpp
	${COMPILER} ${CFLAGS} -o tserver myserver.cpp -std=c++17


clean:
	clear
	rm -f tclient tserver