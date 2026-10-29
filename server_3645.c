#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/stat.h>
#define PROTECTED_FILE "protected_value.txt"

//structure to store session info of logged in user
typedef struct {
    char username[64];
    char token[65];
    time_t lastActivity;
    int active;
} Session;

//Generating the token and null terminates it
//null terminating helps to read it as if it was a string
//read more about this!!
void generateToken(char *token, size_t length) {
    const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < length - 1; i++) {
        token[i] = chars[rand() % strlen(chars)];
    }
    token[length - 1] = '\0';
}

// This creates the salt from a char string and null terminates it
void generateSalt(char *salt, size_t length) {
    const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for(size_t i = 0; i < length - 1; i++) {
        salt[i] = chars[rand() % strlen(chars)];
    }
    salt[length - 1] = '\0';
}

// Hash password + salt using SHA256
void hashPassword(char *password, char *salt, char *hash) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char combined[512];
    snprintf(combined, sizeof(combined), "%s%s", password, salt);
    SHA256((unsigned char*)combined, strlen(combined), digest);
    
    // Convert to hex string
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hash[i*2], "%02x", digest[i]);
    }
    hash[64] = '\0';
}

int saveUser(char *username, char *salt, char *hash) {
    FILE *fp = fopen("/srv/ie2102/IT24103645/users.txt", "a"); // append mode
    if (!fp) return -1;
    
    fprintf(fp, "%s:%s:%s\n", username, salt, hash);
    fclose(fp);
    return 0;
}

int authenticateUser(char *username, char *password) {
    FILE *fp = fopen("/srv/ie2102/IT24103645/users.txt", "r");
    if (!fp) return 0; // file not found

    char fileUser[64];
    char fileSalt[32];
    char fileHash[65];
    char computedHash[65];

    // Read file line by line
    while (fscanf(fp, "%63[^:]:%31[^:]:%64[^\n]\n",
                  fileUser, fileSalt, fileHash) == 3) {

        // Check if username matches
        if (strcmp(fileUser, username) == 0) {

            // Hash the input password with stored salt
            hashPassword(password, fileSalt, computedHash);

            // Compare hashes
            if (strcmp(fileHash, computedHash) == 0) {
                fclose(fp);
                return 1;
            } else {
                fclose(fp);
                return 0;
            }
        }
    }

    fclose(fp);
    return 0;
}

void logEvent(const char *ip, int port, const char *username,
              const char *command, const char *result) {

    FILE *fp = fopen("/srv/ie2102/IT24103645/server_IT24103645.log", "a");
    if (!fp) {
        perror("logEvent fopen failed");
        return;
    }

    time_t now = time(NULL);
    char *timeStr = ctime(&now);
    timeStr[strcspn(timeStr, "\n")] = 0;

    fprintf(fp, "[%s] %s:%d | PID=%d | user=%s | cmd=%s | %s\n",
            timeStr, ip, port, getpid(),
            username ? username : "N/A",
            command, result);

    fclose(fp);
}

void getClientIP(struct sockaddr_in *addr, char *ipbuf, size_t bufsize) {
    inet_ntop(AF_INET, &(addr->sin_addr), ipbuf, bufsize);
}

// FOr get functionality
void readProtectedValue(const char *username, char *buffer, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "/srv/ie2102/IT24103645/%s/protected_value.txt", username);
    
    FILE *fp = fopen(path, "r");
    if (!fp) {
        strncpy(buffer, "EMPTY", size - 1);
        buffer[size - 1] = '\0';
        return;
    }
    if (fgets(buffer, size, fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
    } else {
        strncpy(buffer, "EMPTY", size - 1);
        buffer[size - 1] = '\0';
    }
    fclose(fp);
}

// for set functionality
void writeProtectedValue(const char *username, const char *value) {
    char dirPath[256];
    char filePath[256];

    snprintf(dirPath, sizeof(dirPath), "/srv/ie2102/IT24103645/%s", username);
    snprintf(filePath, sizeof(filePath), "%s/protected_value.txt", dirPath);

    // Create the user directory if it doesn't exist
    if (mkdir(dirPath, 0700) == -1 && errno != EEXIST) {
      perror("mkdir failed");
      return;
    }

    FILE *fp = fopen(filePath, "w");
    if (!fp) return;
    fprintf(fp, "%s\n", value);
    fclose(fp);
}

int userExists(char *username) {
    FILE *fp = fopen("/srv/ie2102/IT24103645/users.txt", "r");
    if (!fp) return 0; // File doesn't exist yet, so user can't exist

    char fileUser[64];
    char fileSalt[32];
    char fileHash[65];

    while (fscanf(fp, "%63[^:]:%31[^:]:%64[^\n]\n", fileUser, fileSalt, fileHash) == 3) {
        if (strcmp(fileUser, username) == 0) {
            fclose(fp);
            return 1; // Found it!
        }
    }

    fclose(fp);
    return 0;
}

// custom handler to handle SIGCHLD
void sigchld_handler(int s) {
    // waitpid() might overwrite errno, so we save and restore it
    int saved_errno = errno;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

int main(){
    //here we set timeNULL to make sure the value is 100% random
    //otherwise just srand() creates a predictable value
    srand(time(NULL));
  
    int sockfd;
    struct sockaddr_in sa;
    
    
    //make empty socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0){
        perror("Socket creation failed!");
        return 1;
    }
    
    //enter details into socket
    sa.sin_family = AF_INET;
    sa.sin_port = htons(50645);
    sa.sin_addr.s_addr = INADDR_ANY;
    
    //making sure socket can be bound to immediately without TIME_WAIT
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    //bind socket to port
    int binderr = bind(sockfd, (struct sockaddr *)&sa, sizeof(sa));
    if(binderr < 0){
        perror("Socket binding failed!");
        return 1;
    }
    
    //listen
    int listenerr = listen(sockfd, 10);
    if(listenerr < 0){
        perror("Failed to listen!");
        return 1;
    }
    
    // SIGCHLD handler setup
    struct sigaction sa_chld;
    sa_chld.sa_handler = sigchld_handler; // Use our new function
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART;        // Prevents system calls from failing when interrupted
    if (sigaction(SIGCHLD, &sa_chld, NULL) == -1) {
        perror("sigaction failed");
        exit(1);
    }

    // We first create the directory needed to store files
    //IMPROTNANT !!! make sure to give 666 permissions to the directory after running client for the first time
    //or else registration will fail
    //command ---> chmod 666 /srv/ie2102/IT24103645
    system("mkdir -p /srv/ie2102/IT24103645");
    
  //ACCEPT LOOP
    while(1){
        struct sockaddr_in cliaddr;
        socklen_t cli_len = sizeof(cliaddr);
        int clifd = accept(sockfd,(struct sockaddr *)&cliaddr, &cli_len);
        
        //log new client connections
        char clientIP[INET_ADDRSTRLEN];
        getClientIP(&cliaddr, clientIP, sizeof(clientIP));
        int clientPort = ntohs(cliaddr.sin_port);
        logEvent(clientIP, clientPort, NULL, "CONNECT", "NEW CONNECTION");
        
        if(clifd < 0){
            perror("Failed to establish connection with client");
            continue;
        }
        
        //fork and create new child
        pid_t pid = fork();
        
        if(pid < 0){
            perror("Failed to fork");
            continue;
        }
        
        //parent process code
        if(pid > 0){
            close(clifd);
        }
        
        //child process code
        if(pid == 0){
            Session session = {0};
            int loginAttempts = 0;
            time_t lockoutTime = 0;
            char clientIP[INET_ADDRSTRLEN];
            getClientIP(&cliaddr, clientIP, sizeof(clientIP));
            int clientPort = ntohs(cliaddr.sin_port);
            
            close(sockfd);
            
  //LOGIN & REGISTRATION COMMAND LOOP
            while(1){
                char loginBuffer[4096] = {0};
                int bytesReceived = 0;
                int len = 0;
                
                // passively waits for login details to be sent by client
                // loop for reading the whole message if one recv cannot
      //RECV() LOOP
                while (1) {
                    int n = recv(clifd, loginBuffer + bytesReceived, sizeof(loginBuffer) - bytesReceived - 1, 0);
                    if (n <= 0) {
                        break;
                    }
                    
                    //we add n after we make sure n is not negative
                    bytesReceived += n;
                    loginBuffer[bytesReceived] = '\0';
                    
                    // we extract the LEN value
                    if (strchr(loginBuffer, '\n') != NULL && len == 0) {
                        sscanf(loginBuffer, "LEN:%d", &len);
                    }
                    
                    // Check for oversized payload
                    if (len > 4096) {
                        char response[512];
                        snprintf(response, sizeof(response), "ERR 413 SID:3645 Payload exceeds maximum size of 4096 bytes\n");
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, NULL, "OVERSIZED", "REJECTED");
                        break;
                    }
                    
                    // Check if we have received the full message (LEN bytes after the "LEN:<n>\n" part)
                    char *payloadStart = strchr(loginBuffer, '\n');
                    if (payloadStart) {
                        payloadStart++;
                        int payloadReceived = bytesReceived - (payloadStart - loginBuffer);
                        if (payloadReceived >= len && len > 0) {
                            break;
                        }
                    }
                }
                
      //PROCESSING LOGIN & REGISTRATIONS
                //store parsed username and password
                char username[64];
                char password[64];
                char *payload = strchr(loginBuffer, '\n');
                if (payload) payload++;
                
                //Check which command it is then parse username and password
                if(sscanf(payload, "REGISTER %63s %63s", username, password) == 2){
                    // Validate username
                    if (strlen(username) < 3 || strlen(username) > 20) {
                        char response[512];
                        snprintf(response, sizeof(response), "ERR 400 SID:3645 Username must be 3-20 characters\n");
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, NULL, "REGISTER", "FAILED - Invalid username");
                        continue;
                    }
                    
                    //before saving we need to make sure username isnt taken
                    if (userExists(username)) {
                        char response[512];
                        snprintf(response, sizeof(response), "ERR 409 SID:3645 User %s already exists\n", username);
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, NULL, "REGISTER", "FAILED - User exists");
                        continue; 
                    }
                    
                    //create hash for the password to store
                    char salt[17];    // 16 chars + null
                    char hash[65];    // 64 chars for SHA256 hex + null
                    generateSalt(salt, sizeof(salt));
                    hashPassword(password, salt, hash);
                    
                    //store username, salt and hash
                    if (saveUser(username, salt, hash) == 0) {
                        //send some confirmation to client
                        char response[512];
                        snprintf(response, sizeof(response), "OK 200 SID:3645 Successfully registered user %s\n", username);
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, username, "REGISTER", "SUCCESS");
                    } else {
                        char response[512];
                        snprintf(response, sizeof(response), "ERR 500 SID:3645 Registration failed\n");
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, username, "REGISTER", "FAILED");
                    }
                    
                } else if (sscanf(payload, "LOGIN %63s %63s", username, password) == 2){
                    // Check if locked out
                    if (lockoutTime > 0 && time(NULL) < lockoutTime) {
                        char response[512];
                        int remaining = lockoutTime - time(NULL);
                        snprintf(response, sizeof(response), "ERR 403 SID:3645 Brute force detected. Account locked for %d seconds\n", remaining);
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, username, "LOGIN", "LOCKED OUT");
                        continue;
                    }
                    
                    //create hash for user password the password to compare
                    int loginResult = authenticateUser(username, password);
                    
                    if(loginResult){
                        generateToken(session.token, sizeof(session.token));
                        strcpy(session.username, username);
                        session.lastActivity = time(NULL);
                        session.active = 1;
                        loginAttempts = 0;
                        lockoutTime = 0;
                        
                        char response[512];
                        snprintf(response, sizeof(response), "OK 200 SID:3645 Login successful. Token: %s\n", session.token);
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, username, "LOGIN", "SUCCESS");
                        break;  // Exit login loop, go to command loop
                        
                    } else {
                        //if error we update abuse counters
                        loginAttempts++;
                        if (loginAttempts >= 5) {
                            lockoutTime = time(NULL) + 300;  // Lockout for 5 minutes
                            char response[512];
                            snprintf(response, sizeof(response), "ERR 403 SID:3645 Too many failed attempts. Account locked for 5 minutes\n");
                            send(clifd, response, strlen(response), 0);
                            logEvent(clientIP, clientPort, username, "LOGIN", "account locked due to failed attempts");
                        } else {
                            char response[512];
                            snprintf(response, sizeof(response), "ERR 401 SID:3645 Username or password is invalid (you have %d attempts remaining)\n", 5 - loginAttempts);
                            send(clifd, response, strlen(response), 0);
                            logEvent(clientIP, clientPort, username, "LOGIN", "FAILED");
                        }
                    }
                    
                } else{
                    printf("Invalid command sent to login loop\n");
                    char response[512];
                    snprintf(response, sizeof(response), "ERR 400 SID:3645 Invalid command\n");
                    send(clifd, response, strlen(response), 0);
                }
                
            }
            
            //before starting interaction loop we should clear buffers
            char tmp[1024];
            while (recv(clifd, tmp, sizeof(tmp), MSG_DONTWAIT) > 0);
            
  //PROTECTED COMMANDS LOOP
            while(session.active){
                char buffer[4096] = {0};
                int bytesReceived = 0;
                int len = 0;
                char clientIP[INET_ADDRSTRLEN];
                getClientIP(&cliaddr, clientIP, sizeof(clientIP));
                int clientPort = ntohs(cliaddr.sin_port);
                
                // Check token expiry (5 minutes inactivity)
                if (time(NULL) - session.lastActivity > 300) {
                    char response[512];
                    snprintf(response, sizeof(response), "ERR 401 SID:3645 Session expired. Please login again\n");
                    send(clifd, response, strlen(response), 0);
                    logEvent(clientIP, clientPort, session.username, "SESSION", "EXPIRED");
                    break;
                }
                
      //RECV() LOOP
                while (1) {
                    int n = recv(clifd, buffer + bytesReceived, sizeof(buffer) - bytesReceived - 1, 0);
                    if (n <= 0) {
                        break;
                    }
                    
                    bytesReceived += n;
                    buffer[bytesReceived] = '\0';
                    
                    if (strchr(buffer, '\n') != NULL && len == 0) {
                        sscanf(buffer, "LEN:%d", &len);
                    }
                    
                    if (len > 4096) {
                        char response[512];
                        snprintf(response, sizeof(response), "ERR 413 SID:3645 Payload exceeds maximum size of 4096 bytes\n");
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, session.username, "OVERSIZED", "REJECTED");
                        break;
                    }
                    
                    char *payloadStart = strchr(buffer, '\n');
                    if (payloadStart) {
                        payloadStart++;
                        int payloadReceived = bytesReceived - (payloadStart - buffer);
                        if (payloadReceived >= len && len > 0) {
                            break;
                        }
                    }
                }
                
                
      //PROCESSING PROTECTED COMMANDS
                char *payload = strchr(buffer, '\n');
                if (payload) payload++;
                
                // Extract token and command
                char receivedToken[65];
                char cmd[64];
                char cmdArgs[256] = {0};
                
                if (sscanf(payload, "TOKEN:%64s %63s", receivedToken, cmd) >= 2) {
                    // Verify token
                    if (strcmp(receivedToken, session.token) != 0) {
                        char response[512];
                        snprintf(response, sizeof(response), "ERR 401 SID:3645 Invalid session token\n");
                        send(clifd, response, strlen(response), 0);
                        printf("Recieved token: %s\n Session token: %s\n", receivedToken, session.token);
                        logEvent(clientIP, clientPort, session.username, cmd, "INVALID TOKEN");
                        continue;
                    }
                    
                    // Update last activity
                    session.lastActivity = time(NULL);
                    
                    // Parse rest of command
                    char *args = strstr(payload, cmd);
                    if (args) {
                        args += strlen(cmd);
                        while (*args == ' ') args++;
                        strncpy(cmdArgs, args, sizeof(cmdArgs) - 1);
                    }
                    
                    // Handle commands
                    if (strcmp(cmd, "GET") == 0) {
                        char value[256];
                        readProtectedValue(session.username, value, sizeof(value));

                        char response[512];
                        snprintf(response, sizeof(response), "OK 200 SID:3645 Value: %s\n", value);
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, session.username, "GET", "SUCCESS");
                     } else if (strcmp(cmd, "SET") == 0) {
                      if (strlen(cmdArgs) == 0) {
                          char response[512];
                          snprintf(response, sizeof(response), "ERR 400 SID:3645 please enter a value to SET\n");
                          send(clifd, response, strlen(response), 0);
                          logEvent(clientIP, clientPort, session.username, "SET", "SET FAILED - no value entered");
                      } else {
                          writeProtectedValue(session.username, cmdArgs);

                          char response[512];
                          snprintf(response, sizeof(response), "OK 200 SID:3645 Value set to: %s\n", cmdArgs);
                          send(clifd, response, strlen(response), 0);
                          logEvent(clientIP, clientPort, session.username, "SET", "SUCCESS");
                      }
                    } else if (strcmp(cmd, "LOGOUT") == 0) {
                        char response[512];
                        snprintf(response, sizeof(response), "OK 200 SID:3645 Logout successful\n");
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, session.username, "LOGOUT", "SUCCESS");
                        break;
                    } else if (strcmp(cmd, "PING") == 0) {
                        char response[512];
                        snprintf(response, sizeof(response), "OK 200 SID:1036 PONG\n");
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, session.username, "PING", "SUCCESS");

                    } else {
                        char response[512];
                        snprintf(response, sizeof(response), "ERR 400 SID:3645 Unknown command: %s\n", cmd);
                        send(clifd, response, strlen(response), 0);
                        logEvent(clientIP, clientPort, session.username, cmd, "UNKNOWN COMMAND");
                    }
                } else {
                    char response[512];
                    snprintf(response, sizeof(response), "ERR 400 SID:3645 Invalid command format. Expected: TOKEN:<token> <command>\n");
                    send(clifd, response, strlen(response), 0);
                    logEvent(clientIP, clientPort, session.username, "INVALID", "BAD FORMAT");
                }
            }
            
            close(clifd);
            exit(0);
        }
    }
    
    close(sockfd);
    return 0;
}
