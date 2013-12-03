
/**
	@file bank.cpp
	@brief Top level bank implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <map>
#include <signal.h>
#include <algorithm>

#include "cryptopp/sha.h"
#include "cryptopp/base64.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/aes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"

#define AES_KEY_LENGTH 32
#define PACKET_SIZE 1024
#define TXTSIZE 320 //size of plain/ciphertext messages AES::BLOCKSIZE * 20
#define NONCE_SIZE 20


using namespace std;

void* client_thread(void* arg);
void* console_thread(void* arg);
int lsock; //Global FD for the network socket

struct user {
	string name;		//Assuming unique, if it matters, could use card ID as a unique value instead
	int balance;
	CryptoPP::SecByteBlock session_token; 
	CryptoPP::SecByteBlock card_info;
	string pin;
};

typedef map<const string,user> user_type; //Should probably chage so int sessid -> user object
//typedef map<pthread_t, CryptoPP::SecByteBlock> session_type;

struct thread_info { 	   		/* Used as argument to thread_start() */
	pthread_t 	thread_id;     /* ID returned by pthread_create() */
	int 			arg;			/* Socket. I think */
	user_type		*users; 		/* Pointer to global users object */
	//session_type	*sessions;		// pointer to global sessions object
	CryptoPP::SecByteBlock session_key;
	string 			username;
};

//user_type users;
pthread_mutex_t users_mutex = PTHREAD_MUTEX_INITIALIZER;
CryptoPP::SecByteBlock atm_private_key;
const char padding [] = "rPvYuxn7gi75oLjco5ZjmgOCcdceYwqFEXKagnKApUDwN54cMrzxFiHTXAfxsh4sOYIf9sOuV8cgrwgCPy66BZOQ32TbafUqp2II9tmChzFlrhmRZGXgvAB9t5C415fbVS0nk7MG1Ze9Fpuh9n2RdsCNeIxhbryxL3POVxTGCMIdIdTeTKj3byV9ugj7U1ZrgKNzuw9PEYIxspHzg67HU5SsWaLMrbijGKFtiVtQ6gV6aMcAGESEQNwi8wdIT5ogwNoKAVY3erCUDoQ66PJ1jK1BcjiJru0gtjMjnEmLFwsxabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/*
 * The process of receiving a message goes:
-split off the MAC (denoted by an underscore)
-append ATMPRIVATEKEY to the message (no MAC)
-sha256 of message with private key
-compare sha256 with MAC, if they match message has not been tampered with
-split off the IV
-in the case of the initial login packet, use the IV and the ATM private key to decrypt the message
-use the user's card key (on file) to decrypt the session key we will be using (easy, did this in ECB mode, because 1) we are cloaked within other crypto and 2) because we should never have the same session key/user key pairing ever again)
-parse the message itself
-check if the user pin matches the pin on file
-construct a message in response - login_success/fail
-respond with the oldnonce as well as a new nonce (oldnonce_newnonce_message)
-send the packet, going through the same MACing process as before, this time using the session key
* 
*/

void pad_packet(char * packet){
	if (packet[strlen(packet)-1] == '\n' || packet[strlen(packet)-1] == ' ')
		packet[strlen(packet)-1] = 0;

	strncat(packet, "___", 3);
	/*
	CryptoPP::AES::BLOCKSIZE = 16
	16*20 = 320
	CBC encyptions must happen in multiples of blocksize
	*/
	strncat(packet, padding, TXTSIZE - strlen(packet)); 
}

void b64encode( const byte* key, int length, string& encoded ){
	CryptoPP::Base64Encoder encoder;
	encoder.Attach( new CryptoPP::StringSink( encoded ) );
	encoder.Put( key, length );
	encoder.MessageEnd();
	
	// remove white space
	encoded.erase( remove_if( encoded.begin(), encoded.end(), ::isspace ), encoded.end() );
}

void b64decode( string encoded, int size, byte* bqdata ){
	CryptoPP::Base64Decoder decoder;
	decoder.Attach( new CryptoPP::ByteQueue(size) );
	decoder.Put( (const byte*) encoded.c_str(), encoded.length() );
	decoder.MessageEnd();
	
	decoder.Get(bqdata, size);
}

void decrypt_session_key( string encrypted_key, CryptoPP::SecByteBlock card_key, byte* destination, int size = AES_KEY_LENGTH ){
	byte enc_session_key[AES_KEY_LENGTH];
	b64decode( encrypted_key, AES_KEY_LENGTH, enc_session_key );

	CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption ecbDecryption(card_key, card_key.size());
	ecbDecryption.ProcessData(destination, enc_session_key, size);	

}

// for checking hash later
void encrypt_session_key(CryptoPP::SecByteBlock session_key, CryptoPP::SecByteBlock card_key, char * out_enc_session_key){	
	CryptoPP::Base64Encoder encoder; //for b64 encodes	
	
	//GET b64 value of session key for debugging
	byte enc_session_key[AES_KEY_LENGTH];

	//encrypt using ECB mode
	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecbEncryption(card_key, card_key.size());
	ecbEncryption.ProcessData(enc_session_key, (byte*)session_key.data(), AES_KEY_LENGTH); //out, in, len
	
	//b64 conversion
	string encryption_output;
	b64encode((const byte*) enc_session_key, AES_KEY_LENGTH, encryption_output);
	

	//put value into out_enc_session_key
	strncpy(out_enc_session_key, encryption_output.c_str(), encryption_output.length());

}

//	-Session stuff
//	-Link user to thread
bool check_hash(std::string message, std::string MAC){
	//	where MAC = SHA256 ( 
	//		E_ATM_PRIVATE_KEY (nonce + "login" + name + pin + E_CARD_KEY(session_key))
	//		_IV+ATMPRIVATEKEY) (No spaces or underscores between IV and ATMPRIVATEKEY)
	//E_ATM_PRIVATE_KEY(nonce, "command", user.name, user.pin, e_card_key(user.session_token), iv+atm_private_key)
	
	//-append ATMPRIVATEKEY to the message (no MAC)
	//-sha256 of message with private key
	//-compare sha256 with MAC, if they match message has not been tampered with
	CryptoPP::Base64Encoder encoder; //for b64 encodes

	//Private key -> b64
	string atm_private_key_b64;
	b64encode( atm_private_key.data(), AES_KEY_LENGTH, atm_private_key_b64 );

	//ONE EXTRA BYTE
	char finalPacket[PACKET_SIZE];
	sprintf(finalPacket,"%s", message.c_str());
	strncat(finalPacket, atm_private_key_b64.c_str(), strlen(atm_private_key_b64.c_str()));



	//get SHA256 digest of packet plaintext message
	byte digest[CryptoPP::SHA256::DIGESTSIZE];
	CryptoPP::SHA256().CalculateDigest(digest, (const byte*) finalPacket, strlen(finalPacket)); //Strlen-1 matches PACKET_REMAINING in atm.cpp


	/*
	following code stolen from http://www.cryptopp.com/wiki/Hash_Functions
	
	B64 encode our SHA256 output, verify with: 
	echo -n "YOUR_STRING" | openssl dgst -sha256 -binary | openssl base64 -e
	*/
	
	//get our SHA256 digest into a string
	std::string digest_output;
	b64encode( digest, sizeof(digest), digest_output );


	//Randomly sleep up to 2 seconds to avoid timing attacks (if they're even possible here)
	int r = rand() % 3;
	sleep(r);
	
	return strcmp(digest_output.c_str(), MAC.c_str()) ? true : false;
//	return (MAC.compare(digest_output) == 0);
}


void decrypt( string encoded, string iv, CryptoPP::SecByteBlock key, char * plaintext ){
	
	// Decode iv string 
	byte ivdata[iv.size()];
	b64decode( iv, iv.size(), ivdata );


	// Decode message	
	byte bqdata[TXTSIZE];
	b64decode( encoded, TXTSIZE, bqdata );
	
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cbcDecryption( key, key.size(), ivdata );
	cbcDecryption.ProcessData( (byte*)plaintext, bqdata, TXTSIZE );
	plaintext[TXTSIZE+1] = '\0';
	
}

vector<string> parse_message(string &msg, char delim = '_' ) {
    vector<string> parsed;
    
    unsigned int pos = msg.find( delim );
    unsigned int initialPos = 0;

    // Decompose statement
    while( pos != std::string::npos && pos < msg.length() ) {
        parsed.push_back( msg.substr( initialPos, pos - initialPos ) );
        initialPos = pos + 1;

        pos = msg.find( delim, initialPos );
	}
    // Add the last one
    parsed.push_back( msg.substr( initialPos ) );
    
    return parsed;
}

bool nonce_check (vector <string> &parsed_plaintext, char * old_nonce, char * new_nonce){
	if (parsed_plaintext.size() < 2){ //we need 2 terms for old nonce and new nonce
		return false; 
	}
	if ( strcmp(parsed_plaintext[0].c_str(), old_nonce) != 0){
		return false; 
	}

	strncpy(old_nonce, parsed_plaintext[1].c_str(), NONCE_SIZE);
	return true;
}

void thread_quit( thread_info* tinfo, bool exit ){
	CryptoPP::SecByteBlock empty_session( 0x00, AES_KEY_LENGTH );
	
	if (!tinfo->username.empty())  { //If user is set, zero their session key
		user_type::iterator it = tinfo->users->find( tinfo->username );
		if (it != tinfo->users->end())
			it->second.session_token.Assign( empty_session, AES_KEY_LENGTH );
	}
	pthread_mutex_unlock(&users_mutex);  //Free users mutex
	if (exit)
		pthread_exit(NULL);
}

void closesock(int param) { //Shutdown
	printf("\nGracefully shutting down...\n");
	fflush(stdout);
	close(lsock);
	exit(1);
}

bool get_card_contents( string& name, char* card_contents ){
	// Zomg we need some card_info! Whhaaaaaa?! Yeah, man. Shit's about to get real.
	CryptoPP::SecByteBlock user_card_DEBUG; //private key for ATM use during login

	// Buildin' a string for the filename
	stringstream card_name;
    card_name << name << ".card";
	string card_file = card_name.str();

	FILE * card = fopen(card_file.c_str(), "r");

	if (card == NULL)
		return false;

	int card_read = fread(card_contents, sizeof(char), AES_KEY_LENGTH, card);

	if (card_read != AES_KEY_LENGTH)
		return false;
	
	fclose(card);

	return true;
}


void init_bank( user_type* users ){ //Create Alice, Bob and Eve user accounts
	CryptoPP::SecByteBlock empty_session( 0x00, AES_KEY_LENGTH );
	
	// atm key
	unsigned char atm_key[AES_KEY_LENGTH] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	atm_private_key.Assign((const byte *)atm_key, AES_KEY_LENGTH);
	
	char card_contents[AES_KEY_LENGTH];
	// Create users and set stuff
	// NOTE: session_token isn't set until they log into an ATM.
	user a;
	a.name = "Alice";
	a.balance = 100;
	a.pin = "abc123";
	a.session_token.Assign( empty_session, AES_KEY_LENGTH );
	get_card_contents(a.name, card_contents);
	a.card_info.Assign((const byte *)card_contents, AES_KEY_LENGTH);
	users->insert( pair<const string, user>("Alice", a) );
	memset( card_contents, '0', AES_KEY_LENGTH );
	
	user b;
	b.name = "Bob";
	b.balance = 50;
	b.pin = "abc456";
	b.session_token.Assign( empty_session, AES_KEY_LENGTH );
	get_card_contents(b.name, card_contents);
	b.card_info.Assign((const byte *)card_contents, AES_KEY_LENGTH);
	users->insert( pair<const string, user>("Bob", b) );
	memset( card_contents, '0', AES_KEY_LENGTH );
	
	user e;
	e.name = "Eve";
	e.balance = 0;
	e.pin = "123abc";
	e.session_token.Assign( empty_session, AES_KEY_LENGTH );
	get_card_contents(e.name, card_contents);
	e.card_info.Assign((const byte *)card_contents, AES_KEY_LENGTH);
	users->insert( pair<const string, user>("Eve", e) );
	
}

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}

	//Close sock on Ctrl-C
	signal(SIGINT, closesock);

	//Create users map
	
	
	unsigned short ourport = atoi(argv[1]);
	
	//socket setup
	lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!lsock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	
	//listening address
	sockaddr_in addr_l;
	addr_l.sin_family = AF_INET;
	addr_l.sin_port = htons(ourport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr_l.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != bind(lsock, reinterpret_cast<sockaddr*>(&addr_l), sizeof(addr_l)))
	{
		printf("failed to bind socket\n");
		return -1;
	}
	if(0 != listen(lsock, SOMAXCONN))
	{
		printf("failed to listen on socket\n");
		return -1;
	}

	//user_type users;
	user_type *users;
	users = new user_type;
	
	init_bank( users );
	
	//session_type *sessions;
	//sessions = new session_type;
	
	thread_info args;
	args.users = users;
	//args.sessions = sessions;

	pthread_t cthread;
	pthread_create(&cthread, NULL, console_thread, &args);
	
	//loop forever accepting new connections
	pthread_t thread_id = 0;
	while(1)
	{
		sockaddr_in unused;
		socklen_t size = sizeof(unused);
		int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
		if(csock < 0)	//bad client, skip it
			continue;
			
		thread_info t;
		t.arg = csock;
		t.thread_id = thread_id++;
		t.users = users;

		pthread_t thread;
		//pthread_create(&thread, NULL, client_thread, (void*)csock);
		pthread_create(&thread, NULL, client_thread, &t);

	}
}

void build_packet( string& packet_builder, thread_info* tinfo, byte* iv, int csock ){
	user_type::iterator it = tinfo->users->find( tinfo->username );
	char packet[PACKET_SIZE];
	CryptoPP::AutoSeededRandomPool rng;
	// packet_builder now contains:
	//	new_nonce + old_nonce + command + result
	// add encrypted session_key
	char enc_session_key[AES_KEY_LENGTH];
	encrypt_session_key( tinfo->session_key, it->second.card_info, enc_session_key );
	packet_builder.append(enc_session_key);
	// copy for SHA later
	string sha_builder = packet_builder;
	// Create packet and pad it
	strncpy( packet, packet_builder.c_str(), packet_builder.size() );
	packet[packet_builder.size()] = '\0';
	pad_packet(packet);
	
	// Encrypt packet using CBC
	int message_size = strlen(packet); //this is important, as encrypted packet may contain \0s
	//IMPORTANT: Generate a new IV each time. IV reuse is NOT OK
	rng.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(tinfo->session_key, tinfo->session_key.size(), iv);
	cbcEncryption.ProcessData((byte*)packet, (byte*)packet, message_size);

	string encryption_output;
	b64encode( (const byte*)packet, message_size, encryption_output );
	
	packet_builder = encryption_output;
	
	string iv_64;
	b64encode( iv, CryptoPP::AES::BLOCKSIZE, iv_64 );
	packet_builder.push_back( '_' );
	packet_builder.append( iv_64 );
	
	// Append and encrypt SHA stuff
	sha_builder.append( iv_64 );
	byte digest[CryptoPP::SHA256::DIGESTSIZE];


	//Private key -> b64
	string atm_private_key_b64;
	b64encode( atm_private_key.data(), AES_KEY_LENGTH, atm_private_key_b64 );

	if (strlen(packet_builder.c_str()+ strlen(atm_private_key_b64.c_str()))+1 > PACKET_SIZE) {
		printf("Packet too large: cannot return!\n");
		return;
	}


	//ONE EXTRA BYTE
	char macPACKET[PACKET_SIZE];
	sprintf(macPACKET,"%s", packet_builder.c_str());
	strncat(macPACKET, atm_private_key_b64.c_str(), strlen(atm_private_key_b64.c_str())); //SEGFAULT

	//get SHA256 digest of packet plaintext message
	CryptoPP::SHA256().CalculateDigest(digest, (const byte*) macPACKET, strlen(macPACKET)); //Strlen-1 matches PACKET_REMAINING in atm.cpp


	/*
	following code stolen from http://www.cryptopp.com/wiki/Hash_Functions
	
	B64 encode our SHA256 output, verify with: 
	echo -n "YOUR_STRING" | openssl dgst -sha256 -binary | openssl base64 -e
	*/
	
	//get our SHA256 digest into a string
	std::string digest_output;
	b64encode( digest, sizeof(digest), digest_output );

	packet_builder.push_back( '_' );
	packet_builder.append(digest_output);
	
	strncpy( packet, packet_builder.c_str(), packet_builder.length() );
	int flength = packet_builder.length();

	
	//send the new packet back to the client
	if(sizeof(int) != send(csock, &flength, sizeof(int), 0))
	{
		printf("[bank] fail to send packet length\n");
		//break;
	}
	if(flength != send(csock, (void*)packet, flength, 0))
	{
		printf("[bank] fail to send packet\n");
		//break;
	}
}

void* client_thread(void* arg) //Handle ATM connections
{
	//int csock = (int)arg;
	struct thread_info *tinfo;
	tinfo = (thread_info *) arg;
	int csock = tinfo->arg;
	user_type *users = tinfo->users; //Local users = parent thread's users (in theory)
	//session_type *sessions = tinfo->sessions; 
	
	printf("[bank] client ID #%d connected\n", csock);
	
	//input loop
	unsigned int length;
	char packet[1024];
	string packet_builder;
	char old_nonce[NONCE_SIZE];
	char new_nonce[NONCE_SIZE];
	byte iv[CryptoPP::AES::BLOCKSIZE];
	CryptoPP::AutoSeededRandomPool rng;
	rng.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
	bool first = true;
	CryptoPP::SecByteBlock empty_session(0x00, AES_KEY_LENGTH);

	while(1) { 
		//read the packet from the ATM
		if(sizeof(int) != recv(csock, &length, sizeof(int), 0))
			break;
		if(length >= 1024)
		{
			printf("packet too long\n");
			break;
		}
		if(length != recv(csock, packet, length, 0))
		{
			printf("[bank] fail to read packet\n");
			break;
		}
		
		packet[length] = '\0';
		//printf("Read %d bytes of packet: %s\n", length, packet); 

		// Convert to standard string because lazy
		string msg(packet, strlen(packet));
		
		//Split message into parsed[i] as 3 parts
		//	parsed[0] = E_ATM_PRIVATE_KEY(nonce + "login" + name + pin + E_CARD_KEY(session_key))
		//	parsed[1] = IV
		//	parsed[2] = MAC
		vector<string> parsed = parse_message(msg);
		
		//VALIDATE hash
		if (check_hash(parsed[0]+"_"+parsed[1], parsed[2])) {
			printf("bad_message\n");
			continue; //Don't even send a response (how could we?)
		}
		
		//DECRYPT
		string plaintext;
		char pt [PACKET_SIZE];

		//Attempt to decrypt message with atm_private_key to see if it's a login message
		decrypt( parsed[0], parsed[1], atm_private_key, pt );

		if (string(pt).find("login") != string::npos) {
			first = true;
		}

		
		// First message is the ATM decryption process
		if( first ){
			decrypt( parsed[0], parsed[1], atm_private_key, pt );
			plaintext = pt;
		}
		// Everything else uses session_key
		else{
			decrypt( parsed[0], parsed[1], tinfo->session_key, pt );
			plaintext = pt;
			
		}
		
		parsed = parse_message( plaintext );		
		// Parsed messages should be:
		//	parsed[0] = old_nonce
		//	parsed[1] = new_nonce
		//	parsed[2] = action
		// 	parsed[3] = argument(s)
		
		string action = parsed[2];
		if(first)
			action = parsed[1];
		
		// clear packet builder.
		packet_builder.clear();
		
		// Check nonce
		if( !first ){
			strncpy(old_nonce, parsed[0].c_str(), NONCE_SIZE);
			strncpy(new_nonce, parsed[1].c_str(), NONCE_SIZE);
			bool nonce_ok = nonce_check( parsed, old_nonce, new_nonce );
			if( !nonce_ok ){
				printf("Bad nonce\n");
				thread_quit( tinfo, 0 );
			}
		}
		else{
			// Copy nonce
			strncpy( old_nonce, parsed[0].c_str(), NONCE_SIZE );
		}
		// make new nonce
		snprintf(new_nonce, NONCE_SIZE, "%u", rand());
		
		// add new nonces to packet
		packet_builder.append( old_nonce );
		packet_builder.push_back( '_' );
		packet_builder.append( new_nonce );
		packet_builder.push_back( '_' );	

		bool sent = false; //have we already replied
		
		// First action must be logging in and setting the session key
		if (first && action == "login") {
			// parsed[2] = name
			// parsed[3] = pin
			// parsed[4] = encrypted session_key
			user_type::iterator it = users->find(parsed[2]);
			// Set session in tinfo
			byte session[AES_KEY_LENGTH];
			
			decrypt_session_key( parsed[4], it->second.card_info, session );
			tinfo->session_key.Assign( session, AES_KEY_LENGTH );
			tinfo->username = parsed[2];
			
			// Make sure user exists
			if( it == (*users).end() ){
				printf("invalid user\n");
				packet_builder.append("login_fail_" );
				sent = true;
				sleep(5);
				build_packet( packet_builder, tinfo, iv, csock );
				thread_quit( tinfo, 0 );
			}
			// Check pin
			else if( parsed[3] != it->second.pin ){
				printf("invalid pin\n");
				packet_builder.append("login_fail_" );
				sent = true;
				build_packet( packet_builder, tinfo, iv, csock );
				thread_quit( tinfo, 0 );
			}
			else if( it->second.session_token != empty_session ){
				printf("already logged in\n");
				packet_builder.append("login_fail_" );
				sent = true;
				build_packet( packet_builder, tinfo, iv, csock );
				thread_quit( tinfo, 0 );
			}
			else{
				// All is well. Set user session and append packet message		
				it->second.session_token.Assign( session, AES_KEY_LENGTH );
				
				packet_builder.append("login_ok_" );
			}
		}
		
		else if( !first && action == "login" ){
			printf( "Already logged in." );
			packet_builder.append("login_fail_" );
			sent = true;
			build_packet( packet_builder, tinfo, iv, csock );
			thread_quit( tinfo, 0 );
		}
		else if( first && action != "login" ){
			printf( "You must log in first." );
			packet_builder.append( action );
			packet_builder.append( "_fail_" );
			sent = true;
			build_packet( packet_builder, tinfo, iv, csock );
			thread_quit( tinfo, 0 );
		}

		//GET MUTEX
		pthread_mutex_lock(&users_mutex);
		
		user_type::iterator it = users->find(tinfo->username);

		if (action == "balance") {
			// parsed[3] = ''
			//printf("%s: %s, %s\n",action.c_str() ,arg.c_str(), arg2.c_str());
			//Return this user -> balance

			int val = it->second.balance;
			char balance[10];
			sprintf( balance, "%d", val );
			packet_builder.append( "balance_" );
			packet_builder.append( balance );
			packet_builder.push_back( '_' );
		}

		if (action == "withdraw") {
			// parsed[3] = amount
			//printf("%s: %s, %s\n",action.c_str() ,arg.c_str(), arg2.c_str());
			//This user -> balance-=X
			
			//withdraw 100
			int sub = atoi(parsed[3].c_str());
			
			if(sub < 0) {
				packet_builder.append("withdraw_fail_"); //error
			}else if(it->second.balance >= sub) {
				it->second.balance -= sub;
				packet_builder.append("withdraw_ok_");
			}else{
				packet_builder.append("withdraw_fail_"); //Insufficient funds
			}

		}
		//transfer
		if (action == "transfer") {
			// parsed[4] = amount
			// parsed[3] = other user
			//Assert X > 0

			//This user -> balance-=X
			//User Y -> balance+=X
			
			//transfer bob 100
			
			//Assert >0 and existing funds
			int sub = atoi(parsed[4].c_str());

			if(sub < 0) {
				packet_builder.append("transfer_fail_"); //error

			}else if(it->second.balance >= sub) {
				printf("Transfer %d to %s\n", sub, parsed[3].c_str());

				user_type::iterator thisItr = (*users).find(parsed[3]); 
				if (thisItr != (*users).end()) {
					//Take money
					it->second.balance -= sub;
					thisItr->second.balance += sub;

					packet_builder.append("transfer_ok_"); 
				}else{
					packet_builder.append("transfer_fail_"); //Target user not found
				}
			}else{
				sprintf(packet,"transfer_fail_"); //Insufficient funds
			}

		}
		//logout
		if (action == "logout") {
			user_type::iterator it = users->find(tinfo->username);
			it->second.session_token.Assign( empty_session, AES_KEY_LENGTH );
			packet_builder.append("logout_ok_");
			build_packet( packet_builder, tinfo, iv, csock );
			sent = true;
			//Don't actually quit the thread, just reset the variables
			thread_quit( tinfo, 0 );
		}

		//Free mutex
		pthread_mutex_unlock(&users_mutex);
		
		if(!sent)
			build_packet( packet_builder, tinfo, iv, csock );
		
		printf("\nbank> ");
		fflush(stdout);
	
		if( first ){
			first = false;
		}
	}

	printf("[bank] client ID #%d disconnected\n", csock);
	user_type::iterator it = users->find(tinfo->username);
	it->second.session_token.Assign( empty_session, AES_KEY_LENGTH );

	close(csock);
	return NULL;
}

void* console_thread(void* arg) //CLI for back-end/testing
{
	struct thread_info *tinfo;
	tinfo = (thread_info *) arg;
	user_type *users = tinfo->users;

	char buf[80];
	while(1)
	{
		printf("bank> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline

		string msg = buf;

		vector<string> parsed = parse_message( msg, ' ' );
		
		if( parsed[0].compare("users") == 0 ){
			printf("All users:\n");
			for (user_type::iterator it=(*users).begin(); it!=(*users).end(); ++it)
				printf("%s => %s & %d\n", it->first.c_str(), it->second.name.c_str(), it->second.balance);
		}
		
		if( parsed[0].compare("balance") == 0 ){
			string name = parsed[1];
			
			user_type::iterator it = (*users).find(name);
			if( it != (*users).end() ){
				int balance = it->second.balance;
				printf("Balance for %s is %d\n", name.c_str(), balance);
			}
			else{
				printf("User not found\n");
			}
		}
		
		if( parsed[0].compare("deposit") == 0 ){
			string name = parsed[1];
			int amount = atoi( parsed[2].c_str() );
			
			user_type::iterator it = (*users).find(name);
			if( it != (*users).end() ){
				it->second.balance += amount;
				printf("Balance for %s is now %d\n", name.c_str(), it->second.balance);
			}
			else{
				printf("User not found\n");
			}
		}

	}
	return NULL; //maybe?
}
