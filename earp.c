#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PING_CMD "ping -c 1 -W 1 %s > /dev/null 2>&1"
#define MAX_ENTRIES 256

typedef struct {
    char ip[16];
    char mac[18];
} Device;

int get_mac(const char *ip, char *mac) {
    FILE *arp = fopen("/proc/net/arp", "r");
    if (!arp) return 0;

    char line[256];
    fgets(line, sizeof(line), arp); // Skip header

    while (fgets(line, sizeof(line), arp)) {
        char current_ip[16], current_mac[18], dummy[10];
        if (sscanf(line, "%15s %*s %*s %17s %*s %*s", 
                  current_ip, current_mac) == 2) {
            if (strcmp(current_ip, ip) == 0 && 
                strcmp(current_mac, "00:00:00:00:00:00") != 0) {
                strcpy(mac, current_mac);
                fclose(arp);
                return 1;
            }
        }
    }

    fclose(arp);
    return 0;
}

void discover_devices(const char *network_prefix, Device *devices, int *count) {
    *count = 0;
    
    // Ping all addresses in the subnet
    for (int i = 1; i < 255; i++) {
        char ip[16];
        snprintf(ip, sizeof(ip), "%s.%d", network_prefix, i);
        
        char cmd[100];
        snprintf(cmd, sizeof(cmd), PING_CMD, ip);
        system(cmd);
        
        // Check if we got a MAC for this IP
        char mac[18] = "Unknown";
        if (get_mac(ip, mac)) {
            strcpy(devices[*count].ip, ip);
            strcpy(devices[*count].mac, mac);
            (*count)++;
        }
    }
}

void print_devices(Device *devices, int count) {
    printf("Active Devices in Network:\n");
    printf("--------------------------\n");
    printf("%-15s %-17s\n", "IP Address", "MAC Address");
    printf("--------------------------\n");
    
    for (int i = 0; i < count; i++) {
        printf("%-15s %s\n", devices[i].ip, devices[i].mac);
    }
    
    printf("--------------------------\n");
    printf("Total: %d devices\n", count);
}

int main() {
    Device devices[MAX_ENTRIES];
    int count;
    
    printf("Discovering devices on 192.168.52.0/24...\n");
    discover_devices("192.168.52", devices, &count);
    print_devices(devices, count);
    
    return 0;
}
