#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARP_ENTRIES 100
#define LINE_BUFFER 256

typedef struct {
    char ip[16];
    char hw_type[10];
    char flags[10];
    char mac[18];
    char mask[10];
    char device[16];
} ArpEntry;

int read_arp_table(ArpEntry entries[], int max_entries) {
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp) {
        perror("Failed to open /proc/net/arp");
        return -1;
    }

    char line[LINE_BUFFER];
    int count = 0;
    
    // Skip header line
    fgets(line, sizeof(line), fp);

    while (fgets(line, sizeof(line), fp) && count < max_entries) {
        ArpEntry *entry = &entries[count];
        
        // Parse line: IP HW_type Flags HW_address Mask Device
        int matched = sscanf(line, 
                           "%15s %9s %9s %17s %9s %15s",
                           entry->ip,
                           entry->hw_type,
                           entry->flags,
                           entry->mac,
                           entry->mask,
                           entry->device);
        
        if (matched == 6) {
            count++;
        }
    }

    fclose(fp);
    return count;
}

void print_arp_table(ArpEntry entries[], int count) {
    printf("\nARP Table (from /proc/net/arp):\n");
    printf("------------------------------------------------------------\n");
    printf("%-15s %-10s %-8s %-17s %-8s %-10s\n", 
           "IP", "HW Type", "Flags", "MAC", "Mask", "Device");
    printf("------------------------------------------------------------\n");
    
    for (int i = 0; i < count; i++) {
        printf("%-15s %-10s %-8s %-17s %-8s %-10s\n",
               entries[i].ip,
               entries[i].hw_type,
               entries[i].flags,
               entries[i].mac,
               entries[i].mask,
               entries[i].device);
    }
    printf("------------------------------------------------------------\n");
    printf("Total entries: %d\n", count);
}

int main() {
    ArpEntry arp_entries[MAX_ARP_ENTRIES];
    int entry_count = read_arp_table(arp_entries, MAX_ARP_ENTRIES);
    
    if (entry_count > 0) {
        print_arp_table(arp_entries, entry_count);
    } else {
        printf("No ARP entries found or error reading ARP table.\n");
    }
    
    return 0;
}
