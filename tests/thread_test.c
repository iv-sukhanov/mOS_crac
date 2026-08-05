#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>
#include <mach/mach.h>
#include <signal.h>

#define NWORKERS 3

typedef struct {
    pthread_t pt;
    mach_port_t mp;
} worker_info_t;

static worker_info_t workers[NWORKERS];
static atomic_uint ready_count = 0;
static atomic_bool stop = false;
static struct {
    uint64_t pc;
} regs;

void* worker_fn(void* arg) {
    int ind = (int)(intptr_t)arg;
    workers[ind].pt = pthread_self();
    mach_port_t mp = pthread_mach_thread_np(pthread_self());
    if (mp != mach_thread_self()) {
        printf("for worker #%d the port is not matching %d != %d\n", ind, mp, mach_thread_self());
    }
    workers[ind].mp = mp;
    atomic_fetch_add(&ready_count, 1);

    volatile counter = 0;
    while (!atomic_load(&stop)) counter++;

    printf("worker #%d finished\n", ind);

    return NULL;
}

void* action_fn(int sig, siginfo_t* info, void *ctx) {
    arm_thread_state64_t state = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    regs.pc = (uint64_t)arm_thread_state64_get_pc(state);
}

int main(void) {

    const struct sigaction act = {
        .sa_flags = SA_SIGINFO,
        .__sigaction_u.__sa_sigaction = action_fn
    };

    pthread_t tids[NWORKERS];
    for (int i = 0; i < NWORKERS; i++) {
        int rc = pthread_create(tids[i], NULL, worker_fn, (void*)(intptr_t)i);
        if (rc != 0) {
            printf("cannot create a pthread: %d\n", rc);
            return 1;
        }
    }

    while (atomic_load(&ready_count) != NWORKERS) usleep(1000);

    pthread_t self_tp = pthread_self();
    mach_port_t self_mp = mach_thread_self();
    printf("main thread: tp=%p mc=0x%x\n", (void*)self_tp, self_mp);
    for (int i = 0; i < NWORKERS; i++) {
        printf("worker: tp=%p mc=0x%x\n", (void*)workers[i].pt, workers[i].mp);
    }

    thread_act_array_t act_list;
    mach_msg_type_number_t act_number;
    kern_return_t rc = task_threads(mach_task_self(), &act_list, &act_number);
    for (int i = 0; i < act_number; i++) {
        thread_act_t curr_mp = act_list[i];
        pthread_t curr_pt = pthread_from_mach_thread_np(curr_mp);

        bool matched = false;
        for (int j = 0; j < NWORKERS; j++) {
            if (curr_mp == workers[j].mp && curr_pt == workers[j].pt) {
                printf("match! worker #%d tp=%p mc=0x%x\n", (void*)curr_pt, curr_mp);
                matched = true;
                break;
            }

            if (curr_mp == self_mp && curr_pt == self_tp) {
                printf("match! main thread #%d tp=%p mc=0x%x\n", (void*)curr_pt, curr_mp);
                matched = true;
                break;
            }
        }

        if (!matched) {
            printf("no match for tp=%p mc=0x%x\n", (void*)curr_pt, curr_mp);
        }
    }
    vm_deallocate(mach_task_self(), &act_list, sizeof(thread_act_t)*act_number);
}