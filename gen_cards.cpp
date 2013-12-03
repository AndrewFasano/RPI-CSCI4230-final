#include "cryptopp/sha.h"
#include "cryptopp/base64.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/aes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"

#include <stdlib.h>
#include <stdio.h>

#define AES_KEY_LENGTH 32

/*
This code generates ATM user cards. These cards contain 256 byte AES
keys
*/

int main(int argc, char * argv[]){
	if (argc != 2){
		printf("USAGE: %s NEW_CARDHOLDER_NAME\n", argv[0]);
		exit(1);
	}
	CryptoPP::AutoSeededRandomPool rng;
	CryptoPP::SecByteBlock card_key(0x00, AES_KEY_LENGTH);
	rng.GenerateBlock(card_key, card_key.size());
	
	char filename[25];
	strncpy(filename, argv[1], strlen(argv[1]));
	strcat(filename, ".card");

	FILE * card = fopen(filename, "w");
			
	if (card == NULL){
		printf("Could not create card %s.", filename);
		exit(1);
	}

	fwrite(card_key, 1, AES_KEY_LENGTH, card);

	fclose(card);

}
