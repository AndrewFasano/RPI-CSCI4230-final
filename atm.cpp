/**
	@file atm.cpp
	@brief Top level ATM implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <vector>
#include <iostream>
#include <sstream>
#include <string>

#include "cryptopp/sha.h"
#include "cryptopp/base64.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/aes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"

#define AES_KEY_LENGTH 32 //32 bytes = 256 bits, max security
#define PACKET_SIZE 1024
#define PACKET_REMAINING(packet) PACKET_SIZE-strlen(packet)
#define USERNAME_MAX_LEN 15
#define TXTSIZE 320 //size of plain/ciphertext messages AES::BLOCKSIZE * 20
#define NONCE_SIZE 20

using namespace std;

int sock; //Global FD for the network socket
CryptoPP::SecByteBlock atm_private_key; //private key for ATM use during login
const char padding [] = "rPvYuxn7gi75oLjco5ZjmgOCcdceYwqFEXKagnKApUDwN54cMrzxFiHTXAfxsh4sOYIf9sOuV8cgrwgCPy66BZOQ32TbafUqp2II9tmChzFlrhmRZGXgvAB9t5C415fbVS0nk7MG1Ze9Fpuh9n2RdsCNeIxhbryxL3POVxTGCMIdIdTeTKj3byV9ugj7U1ZrgKNzuw9PEYIxspHzg67HU5SsWaLMrbijGKFtiVtQ6gV6aMcAGESEQNwi8wdIT5ogwNoKAVY3erCUDoQ66PJ1jK1BcjiJru0gtjMjnEmLFwsxabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
bool loggedin;

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

int packet_send(char * packet, int sock, CryptoPP::SecByteBlock session_key, const byte * iv){ 
	
	CryptoPP::Base64Encoder encoder; //for b64 encodes

	char finalPacket [PACKET_SIZE];


	pad_packet(packet);

	int message_size = strlen(packet); //this is important, as encrypted packet may contain \0s

	//encrypt the packet using CBC mode
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(session_key, session_key.size(), iv);
	cbcEncryption.ProcessData((byte*)packet, (byte*)packet, message_size);

	std::string encryption_output;
	encoder.Attach( new CryptoPP::StringSink( encryption_output ) );
	encoder.Put( (const byte*) packet, message_size );
	encoder.MessageEnd();

encryption_output.erase( remove_if( encryption_output.begin(), encryption_output.end(), ::isspace ), encryption_output.end() );


	//CODE BELOW DECRYPTS ENCRYPTED PACKET FOR DEBUGGING

	//convert the IV to b64
	std::string iv_str;
	encoder.Attach( new CryptoPP::StringSink( iv_str ) );
	encoder.Put( iv, CryptoPP::AES::BLOCKSIZE );
	encoder.MessageEnd();

	iv_str.erase( remove_if( iv_str.begin(), iv_str.end(), ::isspace ), iv_str.end() );

	//concat ciphertext and IV
	snprintf(finalPacket, PACKET_SIZE, "%s_%s", encryption_output.c_str(), iv_str.c_str());



	std::string atm_private_key_b64;
	encoder.Attach( new CryptoPP::StringSink( atm_private_key_b64 ) );
	encoder.Put( atm_private_key.data(), AES_KEY_LENGTH );
	encoder.MessageEnd();


	atm_private_key_b64.erase( remove_if( atm_private_key_b64.begin(), atm_private_key_b64.end(), ::isspace ), atm_private_key_b64.end() );
	

	/*
	Since we are going to calculate MAC with the private ATM key appended, then remove that,
	we here store the string length before the MAC is done so the original strlen can be restored
	*/
	size_t strlen_finalPacket_pre_mac = strlen(finalPacket);

	strncat(finalPacket, atm_private_key_b64.c_str(), PACKET_REMAINING(finalPacket));


	//get SHA256 digest of packet plaintext message
	byte digest[CryptoPP::SHA256::DIGESTSIZE];
	CryptoPP::SHA256().CalculateDigest(digest, (const byte*) finalPacket, strlen(finalPacket));

	/*
	following code stolen from http://www.cryptopp.com/wiki/Hash_Functions
	
	B64 encode our SHA256 output, verify with: 
	echo -n "YOUR_STRING" | openssl dgst -sha256 -binary | openssl base64 -e
	*/
	
	//get our SHA256 digest into a string
	std::string digest_output;
	encoder.Attach( new CryptoPP::StringSink( digest_output ) );
	encoder.Put( digest, sizeof(digest) );
	encoder.MessageEnd();

	digest_output.erase( remove_if( digest_output.begin(), digest_output.end(), ::isspace ), digest_output.end() );
	

	//here we restore original packet length
	finalPacket[strlen_finalPacket_pre_mac] = 0; 

	//add an underscore delimiter
	strncat(finalPacket, (const char *) "_", PACKET_REMAINING(finalPacket));

	//construct final packet with MAC appended
	strncat(finalPacket, digest_output.c_str(), PACKET_REMAINING(finalPacket));


	int flength = strlen(finalPacket);

	//send the packet through the proxy to the bank
	if(sizeof(int) != send(sock, &flength, sizeof(int), 0)) {
		printf("fail to send packet length\n");
		return -1;
	}
	if(flength != send(sock, (void*)finalPacket, flength, 0)) {
		printf("fail to send packet\n");
		return -1;
	}
	return 0; //ok, sent
}

void closesock(int param) {
	printf("\nGracefully shutting down...\n");
	fflush(stdout);
	close(sock);
	exit(1);
}

bool init_atm_key(){

	CryptoPP::SecByteBlock atm_private_key_DEBUG; //private key for ATM use during login

	FILE * atm_card = fopen("ATM_PRIVATE_KEY.card", "r");

	if (atm_card == NULL)
		return false;


	char card_contents[AES_KEY_LENGTH];
	int atm_read = fread(card_contents, sizeof(char), AES_KEY_LENGTH, atm_card);

	if (atm_read != AES_KEY_LENGTH)
		return false;
	
	fclose(atm_card);

	atm_private_key.Assign((const byte *)card_contents, AES_KEY_LENGTH);


	return true;
}

/*
This function takes session key and card key and encrypts session key using card key, putting the output in
enc_session_key.

ECB AES is used, because in this case it's ok and easier to handle. We're encrypting something of length 
AES_KEY_LENGTH, which itself will then be encrypted, furthermore, since a new session key is generated each session,
we should never see repeated use of card key to encryt a session key.
*/
void encrypt_session_key(CryptoPP::SecByteBlock session_key, CryptoPP::SecByteBlock card_key, char * out_enc_session_key){	
	CryptoPP::Base64Encoder encoder; //for b64 encodes	
	
	//GET b64 value of session key for debugging

	byte enc_session_key[AES_KEY_LENGTH];

	//encrypt using ECB mode
	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecbEncryption(card_key, card_key.size());
	ecbEncryption.ProcessData(enc_session_key, (byte*)session_key.data(), AES_KEY_LENGTH); //out, in, len
	
	//b64 conversion
	std::string encryption_output;
	encoder.Attach( new CryptoPP::StringSink( encryption_output ) );
	encoder.Put( (const byte*) enc_session_key, AES_KEY_LENGTH );
	encoder.MessageEnd();
	
	encryption_output.erase( remove_if( encryption_output.begin(), encryption_output.end(), ::isspace ), encryption_output.end() );

	
	//put value into out_enc_session_key
	strncpy(out_enc_session_key, encryption_output.c_str(), encryption_output.length());

	
}

/*
This function attempts to parse a plaintext out into it's various part
*/
void plaintext_message_explode(char * plaintext, vector <string> & parsed){

	//find where padding starts, eliminate it
	char * padding_start = strstr(plaintext, "___");
	*padding_start = 0;


	char * underscore_loc = strtok(plaintext, "_");
	while (underscore_loc != NULL){
		parsed.push_back(string(underscore_loc, strlen(underscore_loc)));
		underscore_loc = strtok(NULL, "_");
	}
}

/*
Validates pin numbers, valid pins are 6 alphanumeric characters.
*/
bool validate_pin(char * pin){

	//remove trailing newline
	char * newline = strchr(pin, '\n');
	if (newline != NULL)
		*newline = '\0';

	if (strlen(pin) != 6)
		return false;

	for (int i = 0; i < 6; i++){
		if (!isalnum(pin[i])) //check if char is alphanumeric
			return false;
	}
	return true;
}
/*
Parses out arguments to a transfer request
*/
bool parse_transfer(char * temp, char * amount, char * name){
	char * tok = NULL;

	tok = strtok(temp, " "); //Name
	if (tok == NULL)
		return false;
	strncpy(name, tok, USERNAME_MAX_LEN);

	tok = strtok(NULL, " "); //Amount
	if (tok == NULL)
		return false;

	strncpy(amount, tok, 10);
	return true;
}


void decrypt( string encoded, string iv, CryptoPP::SecByteBlock key, char * plaintext ){	
	// Decode iv string 
/* 
 * 	// tried this and it didn't chanage anything.
	string decodeIv;
	CryptoPP::StringSource(iv, true, new CryptoPP::Base64Decoder(new 
CryptoPP::StringSink(decodeIv))); 
*/

	CryptoPP::Base64Decoder ivDecoder;
	ivDecoder.Attach( new CryptoPP::ByteQueue (iv.size()) );
	ivDecoder.Put( (const byte*) iv.c_str(), iv.size() );
	ivDecoder.MessageEnd();
	
	byte ivdata[iv.size()];
	ivDecoder.Get( ivdata, iv.size() );

	//printf("IV BYTES: %s", (char *) ivdata);

	// Decode message
	CryptoPP::Base64Decoder decoder;
	decoder.Attach( new CryptoPP::ByteQueue (TXTSIZE));
	decoder.Put( (const byte*) encoded.c_str(), encoded.length() );
	decoder.MessageEnd();
	
	byte bqdata[TXTSIZE];
	decoder.Get( bqdata, TXTSIZE );
	
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption cbcDecryption( key, key.size(), ivdata );
	cbcDecryption.ProcessData( (byte*)plaintext, bqdata, TXTSIZE );
	plaintext[TXTSIZE+1] = '\0';
	
}


vector<string> parse_message( string& msg ){
	// Parsed message will be:
	//	parsed[0] = E_ATM_PRIVATE_KEY(nonce + "login" + name + pin + E_CARD_KEY(session_key))
	//	parsed[1] = IV
	//	parsed[2] = MAC
	vector<string> parsed; 
	
	int c = 0; // vector counter (for testing)
	size_t pos = 0;
	
	//msg.erase( remove_if( msg.begin(), msg.end(), ::isspace ), msg.end() );
	// Sorry this is a dumb for loop.
	for( size_t i = 0; c < 3; i = ++pos ){
		pos = msg.find( '_', i );
		parsed.push_back(msg.substr( i, (pos - i) ));
		c++;
	}
	
	return parsed;
}

/*
This function checks that nonces are ok, and ALSO sets up the nonce
for the next round.
*/

bool nonce_check (vector <string> &parsed_plaintext, char * old_nonce, char * new_nonce, char * command){
	if (parsed_plaintext.size() < 2){ //we need 2 terms for old nonce and new nonce
		return false; 
	}
//	if (!strcmp(command, "login") == 0 ){

	if ( strncmp(parsed_plaintext[0].c_str(), new_nonce, NONCE_SIZE) != 0){
		return false; 
	}
	

	strncpy(old_nonce, parsed_plaintext[1].c_str(), NONCE_SIZE);

	return true;
}

/*
bool get_next_old_nonce(vector <string> &parsed_plaintext, char * old_nonce){
	if (parsed_plaintext.size() < 1){
		return false; 
	}
	strncpy(old_nonce, parsed_plaintext[1].c_str(), NONCE_SIZE);

	return true;
}
*/

bool display_output(char * command, vector <string> &parsed_plaintext, char * amount){
	if (parsed_plaintext.size() < 4){ //we need 4 terms for old nonce and new nonce
		return false; 
	}
	if (strcmp(command, parsed_plaintext[2].c_str()) != 0){
		return false; 
	}
	if (strcmp(command, "login") == 0){
		if (strcmp(parsed_plaintext[3].c_str(), "ok") == 0){
			printf ("Login ok\n");
			loggedin = true;
		}
		else{
			printf("Login failed\n");
		}
	}

	else if(strcmp(command, "balance") == 0){
		printf ("Current balance: %s\n", parsed_plaintext[3].c_str());
	}

	else if (strcmp(command, "withdraw") == 0){
		if (strcmp(parsed_plaintext[3].c_str(), "ok") == 0){
			printf ("%s withdrawn\n", amount);
		}
		else{
			printf("Withdraw failed\n");
		}
	}
	else if (strcmp(command, "transfer") == 0){
		if (strcmp(parsed_plaintext[3].c_str(), "ok") == 0){
			printf ("transfered\n");
		}
		else{
			printf("Transfer failed\n");
		}
	}
	else if (strcmp(command, "logout") == 0){
		if (strcmp(parsed_plaintext[3].c_str(), "ok") == 0){
			printf ("Logged out\n");
		}
		else{
			printf("Logout failed\n");
		}
	}
	else{
		printf("%s %s\n", command, parsed_plaintext[3].c_str());
	}

	return true;
}

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
	std::string atm_private_key_b64;
	encoder.Attach( new CryptoPP::StringSink( atm_private_key_b64 ) );
	encoder.Put( atm_private_key.data(), AES_KEY_LENGTH );
	encoder.MessageEnd();


	atm_private_key_b64.pop_back(); //remove extraneous newline
	


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
	encoder.Attach( new CryptoPP::StringSink( digest_output ) );
	encoder.Put( digest, sizeof(digest) );
	encoder.MessageEnd();

	//Try to strip newline
	digest_output.erase( remove_if( digest_output.begin(), digest_output.end(), ::isspace ), digest_output.end() );


	//Randomly sleep up to 2 seconds to avoid timing attacks (if they're even possible here)
	int r = rand() % 3;
	sleep(r);
	
	return strcmp(digest_output.c_str(), MAC.c_str()) ? true : false;
//	return (MAC.compare(digest_output) == 0);
}

void quit(){
	printf("Recieved malformed packet. Quitting.\n");

//	closesock();

}

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}
	
	//socket setup
	unsigned short proxport = atoi(argv[1]);
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!sock)
	{
		printf("fail to create socket\n");
		return -1;
	}

	//Close sock on Ctrl-C
	signal(SIGINT, closesock);

	if (!init_atm_key()){
		printf("Error initializing ATM private key. Is ATM_PRIVATE_KEY.card present?\n");
		printf("Run './gen_keys ATM_PRIVATE_KEY' to generate it if not.\n");
	}

	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(proxport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
	{
		printf("fail to connect to proxy\n");
		return -1;
	}
	
	srand(time(NULL));

	//input loop
	char buf[80]; 
	int sendret;
	loggedin = false;
	char new_nonce[NONCE_SIZE]; //THIS IS THE NONCE WE SEND
	char old_nonce[NONCE_SIZE]; //THIS IS NONCE RECIEVED
	char amount[11]; //amount withdrawn
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::SecByteBlock session_key(0x00, AES_KEY_LENGTH);
	CryptoPP::SecByteBlock card_key(0x00, AES_KEY_LENGTH);
	
	byte iv[CryptoPP::AES::BLOCKSIZE];
	
	char packet[PACKET_SIZE]; //this is the packet we send
	char pbuf[PACKET_SIZE]; //this is a buffer to work with before sending

	while(1)
	{
		printf("atm> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline


		//Data is stored in packet
	
		//SHOULD THIS BE UNSIGNED???
		unsigned int length = 0;

		memset(packet, 0, PACKET_SIZE); //wipe packet out between sends
		memset(pbuf, 0, PACKET_SIZE);

		char command[80];
		strncpy(command,buf,79);
		//Trim it to the first space
		for(int i=0;i<20;i++) {
			if(command[i] == ' ') {
				command[i] = '\0';
				break;
			}
		}
		
		snprintf(new_nonce, NONCE_SIZE, "%u", rand()); //generate a new nonce

		//IMPORTANT: Generate a new IV each time. IV reuse is NOT OK
		rng.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);

		if (!loggedin){

			//Generate session key if not logged in

			rng.GenerateBlock(session_key, session_key.size());
		
			//input parsing: Put result into packet
			if(!strcmp(command, "login")) { //login username pin
				//Read username
				char username[USERNAME_MAX_LEN + 1];
				char * pin;
				strncpy(username,buf+6, USERNAME_MAX_LEN); //read USERNAME_MAX_LEN characters after "login" 
				//Trim username to end at space
				for(int i=0; i < USERNAME_MAX_LEN; i++) {
					if(username[i] == ' ') {
						username[i] = '\0';
						break;
					}
				}


				//try to open username.card file
				char filename[25];
				strncpy(filename, username, 20);
				strcat(filename, ".card");


				FILE * card = fopen(filename, "r");
				

				if (card == NULL){
					printf("Card for user %s card not found. Try again\n", username);
					continue;
				}

				char card_contents[AES_KEY_LENGTH];
				int card_read = fread(card_contents, sizeof(char), AES_KEY_LENGTH, card);
				fclose(card);

				if (card_read != AES_KEY_LENGTH){
					printf("Error while reading card. Try again\n");
					continue;
				}

				card_key.Assign((const byte*) card_contents, AES_KEY_LENGTH);

				//encrypt session key using card key

				char enc_session_key[AES_KEY_LENGTH];

				encrypt_session_key(session_key, card_key, enc_session_key);

				if (enc_session_key == NULL){
					printf("Error encrypting session key\n");
					continue;
				}

				//read 20 characters after "login username[space], (PIN)"
				//strncpy(pin,buf+7+strlen(username), 20);

				//don't bother with pin if in debug	 But now do bother

				pin = getpass("\nENTER PIN PLEASE> "); //no echo


				if(!validate_pin(pin)){
					printf("Sorry, that's not a valid pin number. Please try again.\n");
					continue;
				}

				snprintf(packet, PACKET_REMAINING(packet), "%s_login_%s_%s_%s", new_nonce, username, pin, enc_session_key); 
				
				//E_ATM_key (nonce + login + name + pin + E_card_key(session_key))

				sendret = packet_send(packet, sock, atm_private_key, iv);


			}
			else{
				printf("Please login with the 'login' command to proceed\n");
				continue; //skip to next loop interaction
			}

		}

		else{ //user IS loggedin, can do other stuff

			if(!strcmp(command, "balance")) {
				//Just send request for balance
				snprintf(pbuf, PACKET_REMAINING(pbuf),"%s","balance");

			}
			else if(!strcmp(command, "withdraw")) {

				strncpy(amount, buf+9, 10); //read 10 characters after "withdraw "
				snprintf(pbuf, PACKET_REMAINING(pbuf), "withdraw_%s",amount);
			}

			else if(!strcmp(command, "logout")) {
				//Send logout packet to end session
				snprintf(pbuf, PACKET_REMAINING(pbuf), "%s","logout");
				loggedin = false;
			}

			else if(!strcmp(command, "transfer")) {
				char temp[26];
				char amount [11];
				char name[USERNAME_MAX_LEN + 1];
				strncpy(temp, buf+9, 25); //read 25 chars after "transfer"
				if (!parse_transfer(temp, amount, name)){
					printf("Error parsing transfer command. Please use format 'transfer AMOUNT USERNAME'.\n");
					continue;
				}

				snprintf(pbuf, PACKET_REMAINING(pbuf), "transfer_%s_%s", name, amount);
			}
			
			else if(!strcmp(command, "login")) {
				printf("You are alread logged in. Use the 'logout' command to logout.\n");
				continue;
			}

			else{
				printf("Command not recognized.\n");
				continue; //go to next loop interation
			}

			//FIX NONCE!!!!!!
			//snprintf(new_nonce, NONCE_SIZE, "%u", 0);

			//expect to get new_nonce back
			snprintf(packet, PACKET_REMAINING(packet), "%s_%s_%s", old_nonce, new_nonce, pbuf); 
			sendret = packet_send(packet, sock, session_key, iv);
		}


		if (sendret == -1) //send failed
			break;

		//parse response packet
		if(sizeof(int) != recv(sock, &length, sizeof(int), 0)) {
			printf("fail to read packet length\n");
			break;
		}
		if(length >= 1024) {
			printf("packet too long\n");
			break;
		}
		if(length != recv(sock, packet, length, 0)) {
			printf("fail to read packet\n");
			break;
		}


		string msg(packet, strlen(packet));

		vector<string> parsed = parse_message(msg);

		if (check_hash(parsed[0]+"_"+parsed[1], parsed[2])) {
			quit();
		}

		char plaintext [PACKET_SIZE];
		decrypt( parsed[0], parsed[1], session_key, plaintext );

		vector <string>  parsed_plaintext;
		

		plaintext_message_explode(plaintext, parsed_plaintext);


		

			bool nonce_ok = nonce_check (parsed_plaintext, old_nonce, new_nonce, command);
			if (!nonce_ok)
				quit();

		

		//try to display output
		if ( !display_output(command, parsed_plaintext, amount))
			quit();

		
	}
	
	//cleanup
	close(sock);
	return 0;
}
