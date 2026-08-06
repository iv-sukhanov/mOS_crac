#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>
#include <mach/mach.h>
#include <signal.h>

#define NWORKERS 3
#define NGPREGS 29

typedef struct {
    pthread_t pt;
    mach_port_t mp;
} worker_info_t;

typedef struct {
    uint64_t pc;
    uint64_t sp;
    uint64_t x[29];
} regs_info_t;

static worker_info_t workers[NWORKERS];
static atomic_uint ready_count = 0;
static atomic_bool stop = false;

static regs_info_t regs;
static atomic_bool regs_read = false;

void* worker_fn(void* arg) {
    int ind = (int)(intptr_t)arg;
    workers[ind].pt = pthread_self();
    mach_port_t mp = pthread_mach_thread_np(pthread_self());
    if (mp != mach_thread_self()) {
        printf("for worker #%d the port is not matching %d != %d\n", ind, mp, mach_thread_self());
    }
    workers[ind].mp = mp;
    atomic_fetch_add(&ready_count, 1);

    volatile int counter = 0;
    while (!atomic_load(&stop)) counter++;

    printf("worker #%d finished\n", ind);

    return NULL;
}

void action_fn(int sig, siginfo_t* info, void* ctx) {
    arm_thread_state64_t state = ((ucontext_t*)ctx)->uc_mcontext->__ss;
    regs.pc = (uint64_t)arm_thread_state64_get_pc(state);
    regs.sp = (uint64_t)arm_thread_state64_get_sp(state);
    memcpy(regs.x, state.__x, sizeof(regs.x));

    atomic_store(&regs_read, true);

    char buf[] = "got signal and read the regs\n";
    write(STDOUT_FILENO, buf, sizeof(buf));
}

int main(void) {

    const struct sigaction new_act = {
        .sa_flags = SA_SIGINFO,
        .__sigaction_u.__sa_sigaction = action_fn
    };
    struct sigaction old;

    if (sigaction(SIGUSR1, &new_act, &old) != 0) {
        perror("sigaction failed");
    }
    
    pthread_t tids[NWORKERS];
    for (int i = 0; i < NWORKERS; i++) {
        int rc = pthread_create(&tids[i], NULL, worker_fn, (void*)(intptr_t)i);
        if (rc != 0) {
            printf("cannot create a pthread: %d\n", rc);
            return 1;
        }
    }

    while (atomic_load(&ready_count) != NWORKERS) usleep(1000);

    pthread_t self_pt = pthread_self();
    mach_port_t self_mp = mach_thread_self();
    printf("main thread: tp=%p mc=0x%x\n", (void*)self_pt, self_mp);
    for (int i = 0; i < NWORKERS; i++) {
        printf("worker: tp=%p mc=0x%x\n", (void*)workers[i].pt, workers[i].mp);
    }

    thread_act_array_t act_list;
    mach_msg_type_number_t act_number;
    if (task_threads(mach_task_self(), &act_list, &act_number) != KERN_SUCCESS) {
        fprintf(stderr, "failed to \'task threads\'");
        return 1;
    }

    worker_info_t* suspend_worker = NULL;
    for (uint32_t i = 0; i < act_number; i++) {
        thread_act_t curr_mp = act_list[i];
        pthread_t curr_pt = pthread_from_mach_thread_np(curr_mp);

        bool matched = false;
        for (int j = 0; j < NWORKERS; j++) {
            
            if (curr_mp == workers[j].mp && curr_pt == workers[j].pt) {
                printf("match! worker #%d tp=%p mc=0x%x\n", j, (void*)curr_pt, curr_mp);
                suspend_worker = &workers[j];
                matched = true;
                break;
            }

            if (curr_mp == self_mp && curr_pt == self_pt) {
                printf("match! main thread #%d tp=%p mc=0x%x\n", j, (void*)curr_pt, curr_mp);
                matched = true;
                break;
            }
        }

        if (!matched) {
            printf("no match for tp=%p mc=0x%x\n", (void*)curr_pt, curr_mp);
        }
    }

    bool success = true;
    regs_info_t gs_regs;
    if (suspend_worker != NULL && suspend_worker->pt != self_pt) {

        kern_return_t kr = thread_suspend(suspend_worker->mp);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "couldn't suspend the thread: %d\n", kr);
            success = false;
        } else {
#if defined(__arm64__) || defined(__aarch64__)
            arm_thread_state64_t state;
	        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
            kr = thread_get_state(suspend_worker->mp, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
            if (kr != KERN_SUCCESS) {
                fprintf(stderr, "couldn't get state of the thread: %d\n", kr);
                success = false;
            } else {
                gs_regs.pc = (u_int64_t)arm_thread_state64_get_pc(state);
                gs_regs.sp = (u_int64_t)arm_thread_state64_get_sp(state);
                memcpy(gs_regs.x, state.__x, sizeof(gs_regs.x));
            }
#else
            printf("inter arch is not supported right now");
#endif
            if (thread_resume(suspend_worker->mp) != KERN_SUCCESS) {
                fprintf(stderr, "couldn't resume the thread\n");
                success = false;
            }
        }

    } else {
        fprintf(stderr, "no matched non-self worker was captured\n");
        success = false;
    }

    if (success) {
        pthread_kill(suspend_worker->pt, SIGUSR1);

        while (!atomic_load(&regs_read)) usleep(1000);
        atomic_store(&regs_read, false);
        
        printf("\ngot state, regs from \"get state\" check: sp=0x%llx, pc=0x%llx\n", gs_regs.sp, gs_regs.pc);
        for (int i = 0; i < NGPREGS; i++) {
            printf("gp#%d=0x%llx, ", i, gs_regs.x[i]);
        }
        printf("\n-------\nregs from \"ctx\" check: sp=0x%llx, pc=0x%llx\n", regs.sp, regs.pc);
        for (int i = 0; i < NGPREGS; i++) {
            printf("gp#%d=0x%llx, ", i, regs.x[i]);
        }
        printf("\n\n");
    }

    vm_deallocate(mach_task_self(), (vm_address_t)act_list, sizeof(thread_act_t)*act_number);
    atomic_store(&stop, true);

    for (int i = 0; i < NWORKERS; i++) pthread_join(tids[i], NULL);

    return 0;
}