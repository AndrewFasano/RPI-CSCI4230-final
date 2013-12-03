Team "Cyber Is A Team Sport"

Alexei Bulazel - bulaza@rpi.edu
Halley Coplin - coplih@rpi.edu
Andrew Fasano - fasana@rpi.edu

Our ATM system uses AES to encrypt messages sent between the ATM and the bank.

In our system, each ATM would have a private 256 bit AES key known only to it
and to the central bank. As this is simply a class project, we have implemented
this in the form of a file stored in the directory from which the ATM and Bank
binaries are run from called ATM_PRIVATE_KEY.card. This private key is to be 
treated as if it were part of the binary itself, it is simply stored as a file
to make the development process easier.

User ATM cards are similiar 256 bit AES keys stored as ".card" files in the 
directory from which the program is run.

Encryption during the ATM/bank session is enrypted using a secret  256 bit
AES session key (randomly generated per session).


Please note below that the "+" character between variables denotes that these
variables are concatenated together with a "_" delimeter between them, and "||"
denotes varibles concatenated with no delimiter

Nonces are simply random integers.

Unless otherwise noted, all encryption is carried out in AES CBC mode with a
a randomly generated IV of size CryptoPP::AES::BLOCKSIZE each time.

cardKey refers to the AES key found in each card file.

b64( x ) refers to a base64 encoding of "x"

Padding is arbitrary.

In order to share the secret session key, the first "login" packet is sent in 
a slightly different way

Login packet:

b64(E_ATMPrivateKey (newNonce + "login" + name + userPin + b64(E(AES ECB MODE)_cardKey(sessionKey)) +++ padding )
	+ b64(IV) 
	+ b64( SHA256( b64(E_ATMPrivateKey (nonce + "login" + name + userPin 
					+ b64(E_cardKey(sessionKey)))+ b64(IV) )

After login, all packets are encrypted with the session key. Two nonces are 
sent in each packet, one which came with the previous packet, the other which
is new, and the next packet must include. OldNonce is the response nonce while
newNonce is the new nonce that must be responded with

b64(E_sessionKey (oldNonce + newNonce + message)) + b64(IV) + 
	b64( SHA256( b64(E_sessionKey (oldNonce + newNonce + message)) + b64(IV)))

Messages have the following form. "A" denotes ATM and "B" denotes bank. Again, 
"+" denotes the use of an "_"

A - "login" + name + pin
B - "login" + "ok"
B - "login" + "fail"

A - "balance"
B - "balance" + balance#

A - "withdraw" + amount#
B - "withdraw" + "ok"
B - "withdraw" + "fail"

A - "logout"
B - "logout" + "ok"

A - "transfer" + amount# + username
B - "transfer" + "ok"
B - "transfer" + "fail"

If a message is ever sent that is considered invalid because of any of the 
following reasons, the session is terminated:

	- the MAC SHA has is not valid
	- the message cannot be parsed into three distinct parts denoted by underscores
	- the plaintext message does not contain a valid action
	- the nonce in the message is incorrect
	- any other error in decoding not explicitly mentioned above

When sending packets over the network, the size of the packet is first sent,
with a max size of 1024 (larger packets are rejected), and then the packet itself
is accepted over a socket.


BUGS
	To have multiple threads all sharing the same socket doesn't actually work. So when more than one user connects, there are some issues with threads and only the newest user can send messages to the bank.
