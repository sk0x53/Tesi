#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <stdint.h>
#include <fcntl.h>

#define AFL_MAP_SIZE        (1 << 16)

#define FORKSRV_FD_READ     198
#define FORKSRV_FD_WRITE    199

#define NEW_FORKSERVER_HELLO 0x41464c01

__attribute__((visibility("default")))
uint8_t *__afl_area_ptr = NULL;

__attribute__((visibility("default")))
void (*__forkserver_start_ptr)(void) = NULL;

/*
    setup_shm is executed before the main of the target
    Into this function we also initialize __forkserver_start_ptr 
*/

int standalone=0;

static void write_to_fuzzer(uint32_t value) {
    if (write(FORKSRV_FD_WRITE, &value, 4) != 4) {
        exit(0);
    }
}

static uint32_t read_from_fuzzer(void) {
    uint32_t value = 0;
    if (read(FORKSRV_FD_READ, &value, 4) != 4) {
        exit(0);
    }
    return value;
}


void aflplusplus_forkserver_start(void) {
    if (fcntl(FORKSRV_FD_READ,  F_GETFD) == -1 ||
        fcntl(FORKSRV_FD_WRITE, F_GETFD) == -1) {
        printf("[forkserver] Not running under AFL, skipping\n");
        return;
    }
    write_to_fuzzer(NEW_FORKSERVER_HELLO); //Forkserver hello to the fuzzer
    //The value 0x41464c01 is needed if we run under afl++. Otherwise we send 0
    uint32_t stat=read_from_fuzzer();
    if ((stat^0Xffffffff)!=NEW_FORKSERVER_HELLO){
        printf("Error in the protocol\n");
        printf("The received status is %d\n",(int)stat);
        exit(1);
    }
    write_to_fuzzer(0x00000000);//Complete the handshake without any option set
    write_to_fuzzer(NEW_FORKSERVER_HELLO);/*
        In order to end the handshake we must resend the hello
    */ 
    while (1) {
        stat=read_from_fuzzer();
        memset(__afl_area_ptr, 0, AFL_MAP_SIZE);

        pid_t child_pid = fork();
        if (child_pid < 0) {
            perror("fork");
            exit(1);
        }
        if (child_pid == 0) {
            close(FORKSRV_FD_READ);
            close(FORKSRV_FD_WRITE);
            return; // return to the main of the instrumented binary
        }
        //father
        write_to_fuzzer((uint32_t)child_pid);
        int status = 0;

        waitpid(child_pid, &status, 0);
        write_to_fuzzer((uint32_t)status);
    }
}

void afl_forkserver_start(void) {
    if (fcntl(FORKSRV_FD_READ,  F_GETFD) == -1 ||
        fcntl(FORKSRV_FD_WRITE, F_GETFD) == -1) {
        printf("[forkserver] Not running under AFL, skipping\n");
        return;
    }

    write_to_fuzzer(0); //Forkserver hello to the fuzzer

    while (1) {

        read_from_fuzzer();
        //memset(__afl_area_ptr, 0, AFL_MAP_SIZE);

        pid_t child_pid = fork();
        if (child_pid < 0) {
            perror("fork");
            exit(1);
        }
        if (child_pid == 0) {
            close(FORKSRV_FD_READ);
            close(FORKSRV_FD_WRITE);
            return; // return to the main of the instrumented binary
        }

        write_to_fuzzer((uint32_t)child_pid);
        int status = 0;

        waitpid(child_pid, &status, 0);
        write_to_fuzzer((uint32_t)status);
    }
}

void standalone_forkserver(void) {
    memset(__afl_area_ptr, 0, AFL_MAP_SIZE);

    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        exit(1);
    }
    if (child_pid == 0) {
        return; // return to the main of the instrumented binary
    }
    else{
        int status = 0;

        waitpid(child_pid, &status, 0);
    }

}

__attribute__((constructor))
void init(void) {
    const char *id_str = getenv("__AFL_SHM_ID");
    const char *version_str=getenv("__AFL_PLUSPLUS");

    if(id_str){
        int shm_id = atoi(id_str);
        __afl_area_ptr = shmat(shm_id, NULL, 0);

        if (__afl_area_ptr == (void *)-1) {
            perror("shmat");
            exit(1);
        }

        if(version_str){
            if(strcmp(version_str,"0")==0){ //version=0 mean standard AFL
                __forkserver_start_ptr=&afl_forkserver_start;
                printf("afl used\n");
            }
            else {
                __forkserver_start_ptr=&aflplusplus_forkserver_start;
                printf("afl++ used\n");
            }

        }
        else{
            printf("__AFL_PLUSPLUS env var doesn't found\nI assume running under AFL++");
            __forkserver_start_ptr=&aflplusplus_forkserver_start;
        }
    }
    else{
        //If the __AFL_SHM_ID is not present the binary is runned in standalone mode
        standalone=1;
        __afl_area_ptr=(uint8_t*)malloc(sizeof(uint8_t) * AFL_MAP_SIZE);
        if(__afl_area_ptr==NULL){
            printf("Error in allocating the space\n");
            exit(1);
        }
        __forkserver_start_ptr=&standalone_forkserver;
        printf("Standalone selected\n");
    }

}

__attribute__((destructor))
void afl_forkserver_cleanup(void) {
    if(standalone==1){
        if (__afl_area_ptr) {
            free((void*)__afl_area_ptr);
        }
    }
    else{
        if (__afl_area_ptr) {
            const char *id_str = getenv("__AFL_SHM_ID");
            if (id_str) {
                shmdt(__afl_area_ptr);
            } 
            __afl_area_ptr = NULL;
        }
    }
}