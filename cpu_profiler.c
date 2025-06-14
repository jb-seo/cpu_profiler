#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <math.h>

#define MAX_PROC_NAME 256
#define MAX_LINE 1024
#define HASH_TABLE_SIZE 1024
#define INITIAL_SAMPLES_CAPACITY 1000

// #define USE_PID_TUNE_FOR_SLEEP_ADJ

// CPU usage sample structure
typedef struct {
    long long uptime_ms;  // uptime-based timestamp (ms)
    unsigned long utime;  // user time difference
    unsigned long stime;  // system time difference
} CPUSample;

// Dynamic array structure
typedef struct {
    CPUSample* samples;
    int count;
    int capacity;
} CPUSampleArray;

typedef struct {
    int pid;
    char name[MAX_PROC_NAME];
    unsigned long utime;
    unsigned long stime;
    unsigned long starttime;
    CPUSampleArray cpu_samples;
} ProcessInfo;

// Hash table entry
typedef struct HashEntry {
    ProcessInfo* process;
    struct HashEntry* next;
} HashEntry;

// Hash table structure
typedef struct {
    HashEntry* buckets[HASH_TABLE_SIZE];
    int total_processes;
} ProcessHashTable;

// Global variables
static ProcessHashTable process_table;
static int monitoring_duration_seconds = 0;
static int collection_interval_ms = 0;
static volatile int stop_monitoring = 0;
static long long start_timestamp_ms = 0;  // Program start time (real time)
static long long current_uptime_ms = 0;   // Current collection cycle uptime (cached)

// Hash function
unsigned int hash_pid(int pid) {
    return ((unsigned int)pid) % HASH_TABLE_SIZE;
}

// Read system uptime in ms (using clock_gettime - very fast)
long long get_uptime_ms() {
    struct timespec ts;
    // Use CLOCK_MONOTONIC on Linux (time since boot)
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    }
    return 0;
}

// Get current time in ms
long long get_current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Initialize CPU sample array
void init_cpu_sample_array(CPUSampleArray* array) {
    array->samples = malloc(sizeof(CPUSample) * INITIAL_SAMPLES_CAPACITY);
    array->count = 0;
    array->capacity = INITIAL_SAMPLES_CAPACITY;
}

// Add CPU sample
void add_cpu_sample(CPUSampleArray* array, long long uptime_ms, unsigned long utime_diff, unsigned long stime_diff) {
    if (array->count >= array->capacity) {
        array->capacity *= 2;
        array->samples = realloc(array->samples, sizeof(CPUSample) * array->capacity);
        if (!array->samples) {
            fprintf(stderr, "Failed to expand CPU sample array\n");
            exit(1);
        }
    }
    
    array->samples[array->count].uptime_ms = uptime_ms;
    array->samples[array->count].utime = utime_diff;
    array->samples[array->count].stime = stime_diff;
    array->count++;
}

// Initialize hash table
void init_process_hash_table(ProcessHashTable* table) {
    memset(table->buckets, 0, sizeof(table->buckets));
    table->total_processes = 0;
}

// Find or create process
ProcessInfo* find_or_create_process(ProcessHashTable* table, int pid, const char* name) {
    unsigned int hash = hash_pid(pid);
    HashEntry* entry = table->buckets[hash];
    
    // Find existing process
    if ((entry != NULL) && (entry->process->pid == pid)) {
        return entry->process;
    }
    
    // Create new process
    ProcessInfo* new_process = malloc(sizeof(ProcessInfo));
    if (!new_process) {
        fprintf(stderr, "Failed to allocate memory for process\n");
        return NULL;
    }
    
    new_process->pid = pid;
    strncpy(new_process->name, name, MAX_PROC_NAME - 1);
    new_process->name[MAX_PROC_NAME - 1] = '\0';
    new_process->utime = 0;
    new_process->stime = 0;
    new_process->starttime = 0;
    init_cpu_sample_array(&new_process->cpu_samples);
    
    // Add to hash table
    HashEntry* new_entry = malloc(sizeof(HashEntry));
    if (!new_entry) {
        free(new_process);
        fprintf(stderr, "Failed to allocate memory for hash entry\n");
        return NULL;
    }
    
    new_entry->process = new_process;
    new_entry->next = table->buckets[hash];
    table->buckets[hash] = new_entry;
    table->total_processes++;
    
    return new_process;
}

// Parse process name (remove parentheses)
void parse_process_name(char* dest, const char* src) {
    size_t src_len = strlen(src);
    if (src_len > 2) {
        strncpy(dest, src + 1, src_len - 2);
        dest[src_len - 2] = 0;
    } else {
        strcpy(dest, src);
    }
}

// Read and update process info from stat file
int read_and_update_proc_stat(int pid) {
    char path[64];
    char line[MAX_LINE];
    FILE* fp;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (!fp) return 0;

    if (fgets(line, sizeof(line), fp)) {
        char comm[MAX_PROC_NAME];
        unsigned long utime, stime, starttime;
        
        sscanf(line, "%*d %s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %*d %*d %*d %*d %*d %*d %lu",
               comm, &utime, &stime, &starttime);
        
        char process_name[MAX_PROC_NAME];
        parse_process_name(process_name, comm);
        
        ProcessInfo* process = find_or_create_process(&process_table, pid, process_name);
        if (process) {
            // Calculate difference values only if this is not the first collection
            if (process->utime > 0 || process->stime > 0) {
                unsigned long utime_diff = utime - process->utime;
                unsigned long stime_diff = stime - process->stime;
                // Use cached uptime from current cycle
                add_cpu_sample(&process->cpu_samples, current_uptime_ms, utime_diff, stime_diff);
            }
            
            process->utime = utime;
            process->stime = stime;
            process->starttime = starttime;
        }
    }

    fclose(fp);
    return 1;
}

// Send data to server (save as JSON file here)
void send_data_to_server() {
    FILE* output = fopen("cpu_monitor_data.json", "w");
    if (!output) {
        perror("Failed to create output file");
        return;
    }
    
    fprintf(output, "{\n");
    fprintf(output, "  \"start_timestamp_ms\": %lld,\n", start_timestamp_ms);
    fprintf(output, "  \"monitoring_duration_seconds\": %d,\n", monitoring_duration_seconds);
    fprintf(output, "  \"collection_interval_ms\": %d,\n", collection_interval_ms);
    fprintf(output, "  \"total_processes\": %d,\n", process_table.total_processes);
    fprintf(output, "  \"processes\": [\n");
    
    int first_process = 1;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashEntry* entry = process_table.buckets[i];
        while (entry != NULL) {
            ProcessInfo* process = entry->process;
            
            if (!first_process) {
                fprintf(output, ",\n");
            }
            first_process = 0;
            
            fprintf(output, "    {\n");
            fprintf(output, "      \"pid\": %d,\n", process->pid);
            fprintf(output, "      \"name\": \"%s\",\n", process->name);
            fprintf(output, "      \"samples_count\": %d,\n", process->cpu_samples.count);
            fprintf(output, "      \"cpu_samples\": [\n");
            
            for (int j = 0; j < process->cpu_samples.count; j++) {
                if (j > 0) fprintf(output, ",\n");
                fprintf(output, "        {\"uptime_ms\": %lld, \"utime\": %lu, \"stime\": %lu}",
                       process->cpu_samples.samples[j].uptime_ms,
                       process->cpu_samples.samples[j].utime,
                       process->cpu_samples.samples[j].stime);
            }
            
            fprintf(output, "\n      ]\n");
            fprintf(output, "    }");
            
            entry = entry->next;
        }
    }
    
    fprintf(output, "\n  ]\n");
    fprintf(output, "}\n");
    fclose(output);
    
    printf("Data collected and saved to cpu_monitor_data.json\n");
    printf("Total processes monitored: %d\n", process_table.total_processes);
}

// Memory cleanup
void cleanup_process_table(ProcessHashTable* table) {
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        HashEntry* entry = table->buckets[i];
        while (entry != NULL) {
            HashEntry* temp_entry = entry;
            ProcessInfo* process = entry->process;
            
            free(process->cpu_samples.samples);
            free(process);
            
            entry = entry->next;
            free(temp_entry);
        }
        table->buckets[i] = NULL;
    }
    table->total_processes = 0;
}

// Signal handler
void signal_handler(int sig) {
    if (sig == SIGALRM || sig == SIGINT || sig == SIGTERM) {
        stop_monitoring = 1;
    }
}

#ifdef USE_PID_TUNE_FOR_SLEEP_ADJ
// Timing adjustment using PID controller
void update_timing_adjustment(struct timeval current_time, struct timeval start_time, 
                             long total_count, double* sleep_adjustment_us) {    
    // PID controller variables
    static double error_sum = 0.0;           // Integral term
    static double prev_error = 0.0;          // Previous error for derivative term
    static double filtered_derivative = 0.0;

    // PID controller constants (ultra-conservative settings for maximum stability)
    const double Kp = 0.1;           // Proportional gain (extremely reduced)
    const double Ki = 0.0005;        // Integral gain (extremely reduced)
    const double Kd = 0.02;          // Derivative gain (extremely reduced)
    const double derivative_filter = 0.95; // Derivative filter (maximum noise reduction)
    
    long total_elapsed_us = (current_time.tv_sec - start_time.tv_sec) * 1000000 +
                            (current_time.tv_usec - start_time.tv_usec);
    double actual_interval_us = (double)total_elapsed_us / total_count;
    
    // Error calculation (actual - target, in us)
    double error = actual_interval_us - (collection_interval_ms * 1000.0);
    
    // Reset integral term if error is too large (windup prevention)
    if (fabs(error) > 1000.0) {  // Threshold reduced to 1000us
        error_sum = 0.0;
    } else {
        // Update integral term
        error_sum += error;
        if (error_sum > 5000.0) error_sum = 5000.0;   // Reduced integral limit
        if (error_sum < -5000.0) error_sum = -5000.0;
    }
    
    // Calculate derivative term (with filter applied)
    double raw_derivative = error - prev_error;
    filtered_derivative = derivative_filter * filtered_derivative + (1 - derivative_filter) * raw_derivative;
    
    // Calculate PID output (in us)
    double pid_output = Kp * error +               // Proportional term
                       Ki * (error_sum) +         // Integral term
                       Kd * filtered_derivative;   // Derivative term (filtered)
    
    // Update new adjustment value
    *sleep_adjustment_us += pid_output;
    
    // Apply limits (stricter limits for stability)
    if (*sleep_adjustment_us < -300) *sleep_adjustment_us = -300;  // Reduced limit
    if (*sleep_adjustment_us > 300) *sleep_adjustment_us = 300;
    
    prev_error = error;
}
#endif

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interval_ms> <duration_seconds>\n", argv[0]);
        fprintf(stderr, "Example: %s 1000 300  (collect every 1 second for 5 minutes)\n", argv[0]);
        return 1;
    }

    collection_interval_ms = atoi(argv[1]);
    monitoring_duration_seconds = atoi(argv[2]);
    
    if (collection_interval_ms < 10) {
        fprintf(stderr, "Interval must be at least 10ms\n");
        return 1;
    }

    if (monitoring_duration_seconds < 1) {
        fprintf(stderr, "Duration must be at least 1 second\n");
        return 1;
    }

    // Check valid range the range of INITIAL_SAMPLES_CAPACITY
    long expected_count = (long)monitoring_duration_seconds * 1000 / collection_interval_ms;
    if (expected_count > INITIAL_SAMPLES_CAPACITY) {
        fprintf(stderr, "Expected sample count (%ld) is greater than initial capacity (%d)\n",
                expected_count, INITIAL_SAMPLES_CAPACITY);
        return 1;
    }

    // Set up signal handlers
    signal(SIGALRM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize hash table
    init_process_hash_table(&process_table);
    
    // Record start time
    start_timestamp_ms = get_current_time_ms();
    
    printf("Starting CPU monitoring for %d seconds, collecting every %dms...\n", 
           monitoring_duration_seconds, collection_interval_ms);
        
    struct timeval last_time, current_time, start_time;
    gettimeofday(&last_time, NULL);
    gettimeofday(&start_time, NULL);

    double sleep_adjustment_us = 70;   // Set initial value to 50 (conservative start)
#ifdef USE_PID_TUNE_FOR_SLEEP_ADJ
    long total_count = 0;
#endif

    // Set alarm for monitoring termination
    alarm(monitoring_duration_seconds);

    while (!stop_monitoring) {
        // Read and cache uptime only once for current cycle
        current_uptime_ms = get_uptime_ms();
        
        // Scan /proc directory
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) {
            perror("Failed to open /proc");
            break;
        }

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != NULL) {
            // Process only PID directories (numeric names)
            if (!isdigit(entry->d_name[0])) continue;

            int pid = atoi(entry->d_name);
            read_and_update_proc_stat(pid);
        }
        closedir(proc_dir);

        // Wait until next interval
        gettimeofday(&current_time, NULL);
        long elapsed_us = (current_time.tv_sec - last_time.tv_sec) * 1000000 +
                         (current_time.tv_usec - last_time.tv_usec);
        long sleep_us = collection_interval_ms * 1000 - elapsed_us;


        // Adjust sleep_adjustment_us with PID control every 10 times (more slowly)
#ifdef USE_PID_TUNE_FOR_SLEEP_ADJ
        total_count++;
        if ((total_count % 10) == 0) {  // After 200 samples, every 20 samples
            update_timing_adjustment(current_time, start_time, total_count, &sleep_adjustment_us);
            // Reset count every 200 samples
            if (total_count > 200) {
                total_count = 0;
                gettimeofday(&start_time, NULL);
            }
        }
#endif

        usleep(sleep_us - (long) sleep_adjustment_us);
        gettimeofday(&last_time, NULL);
    }
    
    // Send data
    send_data_to_server();
    
    // Memory cleanup
    cleanup_process_table(&process_table);
    
    return 0;
}
