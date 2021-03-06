/* David Gluckman
 * CS 344 Section 400 Winter 2017
 * Program OTP
 * otp_enc_d.c
 */

// Adapted from server.c by Ben Brewster

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

// Accepts plaintext and key, encrypts message, and sends output to result
void encryptText(char* plaintext, char* key, char* result)
{
	// Clear string to hold result
	memset(result, '\0', sizeof(result));
	int i;
	// Do the math to encrypt each character
	for(i = 0; i < strlen(plaintext); i++)
	{
	        // Convert plain character to 27 math
       		char plainChar;
     		// If it's a space
        	if (plaintext[i] == 32) {
         		// Set it to 0
        		plainChar = 0;
        	}
        	// Else it's an uppercase letter
        	else
       	 	{
         		// Normalize it
        		plainChar = plaintext[i] - 64;
        	}
        
	        // Convert key character to 27 math
        	char keyChar;
        	// If it's a space
        	if (key[i] == 32) {
        		keyChar = 0;
        	}
        	// Else it's an upperase letter
       		else
        	{
        		// Normalize it
        		keyChar = key[i] - 64;
        	}
        
        	// Add plaintext and key and then take modulus
		result[i] = (plainChar + keyChar) % 27;
		// If it's 0, make it a space
		if(result[i] == 0)
		{
			result[i] = 32;
		}
		// Else set it to an uppercase letter
		else
		{
			result[i] += 64;	
		}
	}

	// Return; result is stored in result
	return;
}

int main(int argc, char *argv[])
{
	pid_t pPID = getpid();
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	char recBuffer[200000], sendBuffer[100000], plainBuffer[100000], keyBuffer[100000], handshake[4];
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) error("ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("ERROR on binding");
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	// Track child processes
	pid_t childPIDs[5] = {0};
	int numChildren = 0;

	// Accept up to five connections
	while(1)
	{
		// Check for and clean up completed children
		if(numChildren)
		{
			int childProc;
			int* childExitMethod;
			for(childProc = 0; childProc < 5; childProc++)
			{
				// If a vlid PID and it has finished
				if(childPIDs[childProc] != 0 && waitpid(childPIDs[childProc], &childExitMethod, WNOHANG))
				{
					// Clear the pid
					childPIDs[childProc] = 0;

					// Decrement the pid counter
					numChildren--;
				}
			}
		}

		// If not all connections used, make a new one
		if(numChildren < 5)
		{
			// Fork off new child process
			pid_t forkPID;
			forkPID = fork();
		
			// Handle child and parent processes differently
			// If error
			if(forkPID == -1)
			{
				perror("Fork error\n");
			}
			// If child process
			else if(forkPID == 0)
			{

				// Accept a connection, blocking if one is not available until one connects
				sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
				establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
				if (establishedConnectionFD < 0) perror("ERROR on accept");

				// Get the message from the client
				memset(recBuffer, '\0', sizeof(recBuffer));
				charsRead = recv(establishedConnectionFD, recBuffer, sizeof(recBuffer) - 1, 0); // Read the client's message from the socket
				if (charsRead < 0) perror("ERROR reading from socket");
				//printf("SERVER: I received this from the client: \"%s\"\n", recBuffer);

				// Separate out the handshake, plaintext, and key
				// Handshake
					memset(handshake, '\0', sizeof(handshake));
				char* token = strtok(recBuffer, "**");
				strcpy(handshake, token);
				//printf("Handshake: %s\n", handshake);
				// Test the handshake
				int skipEncrypt = 0;
				if(strcmp(handshake, "enc") != 0)
				{
					skipEncrypt = 1;
				}

				// Separate plaintext
				token = strtok(NULL, "##");
				strcpy(plainBuffer, &token[1]);
				//printf("plaintext: %s\n", plainBuffer);

				// Separate key
				token = strtok(NULL, "@@");
				strcpy(keyBuffer, &token[1]);
				//printf("key: %s\n", keyBuffer);

				// Encrypt the message
				// If handshake failed
				if(skipEncrypt)
				{
					// Send denied code
					memset(sendBuffer, '\0', sizeof(sendBuffer));
					strcpy(sendBuffer, "@@@");
				}
				// Else encrypt the message for sending
				else
				{
					// Perform encryption
					encryptText(plainBuffer, keyBuffer, sendBuffer);
					strcat(sendBuffer, "#");
				}

				// Send encrypted message or denial back to the client
				int bytesSent = 0;
				int bytesLeft = strlen(sendBuffer);
				char* buff = sendBuffer;
				while (bytesLeft)
				{
					bytesSent = send(establishedConnectionFD, buff, strlen(buff), 0); // Send message back
					if (bytesSent < 0) 
					{
						perror("ERROR writing to socket");
						break;
					}
					buff += bytesSent;
					bytesLeft -= bytesSent;
				}
				close(establishedConnectionFD); // Close the existing socket which is connected to the client
				//close(listenSocketFD); // Close the listening socket
				
				exit(0); // Exit normally
			}
			// Else it's the parent process
			else
			{
				// Save the child's pid
				int pidSaved = 0;
				int pidTest = 0;
				while(!pidSaved && pidTest < 5)
				{
					// If the pid holder is empty
					if(childPIDs[pidTest] == 0)
					{
						// Save the forked pid there
						childPIDs[pidTest] = forkPID;
						// Increment the child counter
						numChildren++;
						// Set the saved flag
						pidSaved = 1;
					}
					// Else keep looking
					else
					{
						// Increment the pid test counter
						pidTest++;
					}
				}
			}				
		}
	}

	return 0; 
}
