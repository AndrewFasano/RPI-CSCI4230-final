#crypto++ should installed into /usr/include/cryptopp as it should be according to http://www.cryptopp.com/wiki/Linux
INC=-L/usr/include/ 

all:
	g++ -std=c++0x -Wall $(INC) atm.cpp -lcryptopp -lpthread -o atm -g 
	g++ -Wall $(INC) bank.cpp -o bank -lcryptopp -lpthread -g
	g++ -Wall $(INC) proxy.cpp -o proxy -lpthread -g
