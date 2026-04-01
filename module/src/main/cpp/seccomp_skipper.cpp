#include "zygisk.hpp"
#include <android/log.h>
#include <sys/prctl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_INFO, "bypass_prctl", __VA_ARGS__)
#define TARGET_APP_NAME "com.example.libtests"

#if defined(__aarch64__)
#include "And64InlineHook.hpp"

static int (*orig_prctl)(int, unsigned long, unsigned long, unsigned long, unsigned long);

static FunctionPrologue prctl_backup;

static int hook_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    if (option == PR_SET_SECCOMP) {
        LOGD("Blocked PR_SET_SECCOMP syscall!\n");
        LOGD("Removing the hook!!!\n");
        RevokeHook((void *)prctl, prctl_backup);
        RevokeRWX();
        return 0; 
    }
    return syscall(SYS_prctl, option, arg2, arg3, arg4, arg5);
}
#endif

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }
    
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process && strcmp(process, TARGET_APP_NAME) == 0) {

/* KernelSU does not load it unless it is built for all
architecutres, but "A64HookFunction" only works on AArch64
thus, we simply don't include the logic on the other platforms. */ 

#if defined(__aarch64__)
            LOGD("Injecting And64InlineHook in %s\n", process);
            uint32_t* instr = (uint32_t*)prctl;
            for(int i=0; i<10; i++){
                LOGD("FOUND INSTR %d, 0x%x\n", i, *(instr+i));
            }
            
            A64HookFunction((void *)prctl, (void *)hook_prctl, (void **)&orig_prctl, &prctl_backup);
#else
            LOGD("Hooking skipped.");
#endif

        }
        if (process) env->ReleaseStringUTFChars(args->nice_name, process);
    }

private:
    zygisk::Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MyModule)