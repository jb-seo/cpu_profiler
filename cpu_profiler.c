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

#define MAX_PROC_NAME 256
#define MAX_LINE 1024
#define HASH_TABLE_SIZE 1024
#define INITIAL_SAMPLES_CAPACITY 1000

// CPU 사용량 샘플 구조체
typedef struct {
    long long uptime_ms;  // uptime 기준 timestamp (ms)
    unsigned long utime;  // user time 차이값
    unsigned long stime;  // system time 차이값
} CPUSample;

// 동적 배열 구조체
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

// Hash table 구조체
typedef struct {
    HashEntry* buckets[HASH_TABLE_SIZE];
    int total_processes;
} ProcessHashTable;

// 전역 변수
static ProcessHashTable process_table;
static int monitoring_duration_seconds = 0;
static int collection_interval_ms = 0;
static volatile int stop_monitoring = 0;
static long long start_timestamp_ms = 0;  // 프로그램 시작 시간 (실제 시간)
static long long current_uptime_ms = 0;   // 현재 수집 사이클의 uptime (캐시)

// Hash 함수
unsigned int hash_pid(int pid) {
    return ((unsigned int)pid) % HASH_TABLE_SIZE;
}

// 시스템 uptime을 ms 단위로 읽기 (clock_gettime 사용 - 매우 빠름)
long long get_uptime_ms() {
    struct timespec ts;
    // Linux에서는 CLOCK_MONOTONIC 사용 (부팅 시점부터의 시간)
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    }
    return 0;
}

// 현재 시간을 ms 단위로 가져오기
long long get_current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// CPU 샘플 배열 초기화
void init_cpu_sample_array(CPUSampleArray* array) {
    array->samples = malloc(sizeof(CPUSample) * INITIAL_SAMPLES_CAPACITY);
    array->count = 0;
    array->capacity = INITIAL_SAMPLES_CAPACITY;
}

// CPU 샘플 추가
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

// Hash table 초기화
void init_process_hash_table(ProcessHashTable* table) {
    memset(table->buckets, 0, sizeof(table->buckets));
    table->total_processes = 0;
}

// 프로세스 찾기 또는 생성
ProcessInfo* find_or_create_process(ProcessHashTable* table, int pid, const char* name) {
    unsigned int hash = hash_pid(pid);
    HashEntry* entry = table->buckets[hash];
    
    // 기존 프로세스 찾기
    if ((entry != NULL) && (entry->process->pid == pid)) {
        return entry->process;
    }
    
    // 새 프로세스 생성
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
    
    // Hash table에 추가
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

// 프로세스 이름 파싱 (괄호 제거)
void parse_process_name(char* dest, const char* src) {
    size_t src_len = strlen(src);
    if (src_len > 2) {
        strncpy(dest, src + 1, src_len - 2);
        dest[src_len - 2] = 0;
    } else {
        strcpy(dest, src);
    }
}

// stat 파일에서 프로세스 정보 읽기 및 업데이트
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
            // 첫 번째 수집이 아닌 경우에만 차이값 계산
            if (process->utime > 0 || process->stime > 0) {
                unsigned long utime_diff = utime - process->utime;
                unsigned long stime_diff = stime - process->stime;
                // 현재 사이클에서 캐시된 uptime 사용
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

// 데이터를 서버로 전송 (여기서는 JSON 파일로 저장)
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

// 메모리 정리
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

// 시그널 핸들러
void signal_handler(int sig) {
    if (sig == SIGALRM || sig == SIGINT || sig == SIGTERM) {
        stop_monitoring = 1;
    }
}

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

    // 시그널 핸들러 설정
    signal(SIGALRM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Hash table 초기화
    init_process_hash_table(&process_table);
    
    // 시작 시간 기록
    start_timestamp_ms = get_current_time_ms();
    
    printf("Starting CPU monitoring for %d seconds, collecting every %dms...\n", 
           monitoring_duration_seconds, collection_interval_ms);
        
    struct timeval last_time, current_time, start_time;
    gettimeofday(&last_time, NULL);
    gettimeofday(&start_time, NULL);

    double total_sleep_time = 0.0;
    double sleep_adjustment_us = 50.0;
    long total_count = 0;

    // 모니터링 종료 알람 설정
    alarm(monitoring_duration_seconds);

    while (!stop_monitoring) {
        // 현재 사이클의 uptime을 한번만 읽어서 캐시
        current_uptime_ms = get_uptime_ms();
        
        // /proc 디렉토리 스캔
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) {
            perror("Failed to open /proc");
            break;
        }

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != NULL) {
            // PID 디렉토리만 처리 (숫자로 된 이름)
            if (!isdigit(entry->d_name[0])) continue;

            int pid = atoi(entry->d_name);
            read_and_update_proc_stat(pid);
        }
        closedir(proc_dir);

        // 다음 interval까지 대기
        gettimeofday(&current_time, NULL);
        long elapsed_us = (current_time.tv_sec - last_time.tv_sec) * 1000000 +
                         (current_time.tv_usec - last_time.tv_usec);
        long sleep_us = collection_interval_ms * 1000 - elapsed_us;

        total_count++;

        // 100번에 한번 sleep_adjustment_us를 조정
        if ((total_count % 10) == 0) {
            long total_elapsed_us = (current_time.tv_sec - start_time.tv_sec) * 1000000 +
                                    (current_time.tv_usec - start_time.tv_usec);
            double actual_interval_ms = (double)total_elapsed_us / total_count / 1000.0;
            if (actual_interval_ms > collection_interval_ms) {
                sleep_adjustment_us *= 1.2;
            }
            else if (actual_interval_ms < collection_interval_ms) {
                sleep_adjustment_us /= 1.2;
            }
            if (sleep_adjustment_us < 10) sleep_adjustment_us = 10;  // 최소 10us로 제한
            if (sleep_adjustment_us > 1000) sleep_adjustment_us = 1000;  // 최대 1000us로 제한
            fprintf(stderr, "A: %.5f ms, S: %.2f us\n", actual_interval_ms, sleep_adjustment_us);
        }

        if (sleep_us > sleep_adjustment_us) {
            total_sleep_time += sleep_us / 1000.0;  // ms 단위로 기록
            usleep(sleep_us - (long) sleep_adjustment_us);
        }

        gettimeofday(&last_time, NULL);
    }

    printf("Total sleep time during monitoring: %.2f ms\n", total_sleep_time);  
    
    // 데이터 전송
    send_data_to_server();
    
    // 메모리 정리
    cleanup_process_table(&process_table);
    
    return 0;
}
