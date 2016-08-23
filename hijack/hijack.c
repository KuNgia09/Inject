#include <stdio.h>    
#include <stdlib.h>       
//#include <asm/ptrace.h>    
#include <sys/ptrace.h>    
#include <sys/wait.h>    
#include <sys/mman.h>    
#include <dlfcn.h>    
#include <dirent.h>  
#include <unistd.h>    
#include <string.h>  
#include <stdint.h>
#define pid_t int

#define FUNCTION_NAME_ADDR_OFFSET       0x100  
#define FUNCTION_HOOK_ADDR_OFFSET       0x200
#define FUNCTION_PARAM_ADDR_OFFSET      0x300 
struct pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	int  xfs;
	int  xgs;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};

//获取mmap函数  --libc
//获取dlopen，dlsym等函数 --libdl
const char *libc_path = "/lib/i386-linux-gnu/libc-2.19.so";    
const char *linker_path = "/lib/i386-linux-gnu/libdl-2.19.so";    


int ptrace_getregs(pid_t pid, struct pt_regs * regs)    
{    
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {    
        perror("ptrace_getregs: Can not get register values");    
        return -1;    
    }    
    
    return 0;    
}    
  
int ptrace_setregs(pid_t pid, struct pt_regs * regs)    
{    
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {    
        perror("ptrace_setregs: Can not set register values");    
        return -1;    
    }    
    
    return 0;    
}    
    
int ptrace_continue(pid_t pid)    
{    
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {    
        perror("ptrace_cont");    
        return -1;    
    }    
    
    return 0;    
}    
long ptrace_retval( struct pt_regs * regs)    
{    
    return regs->eax;    
}    
    
long ptrace_ip( struct pt_regs * regs)    
{    

    return regs->eip;    

}    
int ptrace_attach(pid_t pid)    
{    
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {    
        perror("ptrace_attach");    
        return -1;    
    }    
    
    int status = 0;    
    waitpid(pid, &status , WUNTRACED);    
    
    return 0;    
}    
    
int ptrace_detach(pid_t pid)    
{    
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {    
        perror("ptrace_detach");    
        return -1;    
    }    
    
    return 0;    
}  


void* get_module_base(pid_t pid, const char* module_name)    
{    
    FILE *fp;    
    long addr = 0;    
    char *pch;    
    char filename[32];    
    char line[1024];    
    
    if (pid < 0) {    
        /* self process */    
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);    
    } else {    
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);    
    }    
    
    fp = fopen(filename, "r");    
    
    if (fp != NULL) {    
        while (fgets(line, sizeof(line), fp)) {    
            if (strstr(line, module_name)) {    
                pch = strtok( line, "-" );    
                addr = strtoul( pch, NULL, 16 );    
    
                if (addr == 0x8000)    
                    addr = 0;    
    
                break;    
            }    
        }    
    
        fclose(fp) ;    
    }    
    printf("[+] %s handle address is %x\n",module_name,addr);
    return (void *)addr;    
}    
    
void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr)    
{    
    void* local_handle, *remote_handle;    
    
    local_handle = get_module_base(-1, module_name);    
    remote_handle = get_module_base(target_pid, module_name);    
    
    printf("[+] get_remote_addr: local[%x], remote[%x]\n", local_handle, remote_handle);    
    
    void * ret_addr = (void *)((uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle);    
    
    //为什么要加2
    if (!strcmp(module_name, libc_path)) {    
        ret_addr += 2;    
    }  
  
    return ret_addr;

}    
     

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)    
{    
    uint32_t i, j, remain;    
    uint8_t *laddr;    
    
    union u {    
        long val;    
        char chars[sizeof(long)];    
    } d;    
    
    j = size / 4;    
    remain = size % 4;    
    
    laddr = data;    
    
    for (i = 0; i < j; i ++) {    
        memcpy(d.chars, laddr, 4);    
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);    
    
        dest  += 4;    
        laddr += 4;    
    }    
    
    if (remain > 0) {    
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);    
        for (i = 0; i < remain; i ++) {    
            d.chars[i] = *laddr ++;    
        }    
    
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);    
    }    
    
    return 0;    
}    
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params,  struct pt_regs *regs)    
{    
    regs->esp -= (num_params) * sizeof(long) ;  
   // 将mmap函数参数写到stack上 
    ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));    
    
    long tmp_addr = 0x00;    
    regs->esp -= sizeof(long);   
    /**
    push mmap所需要的参数
    push tmp_addr
    */ 
    ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));     
    
    //eip指向mmap
    regs->eip = addr;    
    

    //让被调试进程继续运行
    if (ptrace_setregs(pid, regs) == -1     
            || ptrace_continue( pid) == -1) {    
        printf("error\n");    
        return -1;    
    }    
    
    int stat = 0;  
    waitpid(pid, &stat, WUNTRACED);  
    
    while (stat != 0xb7f) {  
        if (ptrace_continue(pid) == -1) {  
            printf("error\n");  
            return -1;  
        }  
        waitpid(pid, &stat, WUNTRACED);  
    }  
    
    return 0;    
}    
/**
    pid_t target_pid 目标进程id
    func_name 目标函数
    func_addr目标函数地址
    parameters目标函数调用参数
    param_num参数个数
    regs 寄存器
*/    
int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num,  struct pt_regs * regs)     
{    
    printf("[+] Calling %s in target process.\n", func_name);    
    if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)    
        return -1;    
    
    //执行完之后 目标进程是属于挂起的 获取执行mmap函数返回后的regs
    if (ptrace_getregs(target_pid, regs) == -1)    
        return -1;    
    printf("[+] Target process returned from %s, return value=%x, pc=%x \n",     
            func_name, ptrace_retval(regs), ptrace_ip(regs));    
    return 0;    
}    
    
int inject_remote_process(int target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size)    
{    
    int ret = -1;    
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;    
    void *local_handle, *remote_handle, *dlhandle;
    void* libc_handle,*libdl_handle;
    void   *local_mmap,*local_dlopen, *local_dlsym,*local_dlclose,*local_dlerror;    
    uint8_t *map_base = 0;    
 // uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;    
    
     struct pt_regs regs, original_regs;    

    
    uint32_t code_length;    
    long parameters[10];    
    
    printf("[+] Injecting process: %d\n", target_pid);    
    printf("[+] inject so path %s\n", library_path);
    if (ptrace_attach(target_pid) == -1)    
        goto exit;    
    
    if (ptrace_getregs(target_pid, &regs) == -1)    
        goto exit;    
    
    /* save original registers */    
    memcpy(&original_regs, &regs, sizeof(regs));    
    
    /**
    *注意在linux当中 mmap函数是在libc库 而dlopen dlsym 等函数是在libdl库
    *我们可以在ida中所搜export函数验证这一点
    */
    libc_handle = dlopen("libc-2.19.so", RTLD_LAZY);
    if (libc_handle) {
        local_mmap = (unsigned long)dlsym(libc_handle, "mmap");
        dlclose(libc_handle);
    }
    libdl_handle = dlopen("libdl-2.19.so", RTLD_LAZY);
    if (libdl_handle) 
    {
        local_dlopen = (unsigned long)dlsym(libdl_handle, "dlopen");
	    local_dlsym = (unsigned long)dlsym(libdl_handle, "dlsym");
	    local_dlclose = (unsigned long)dlsym(libdl_handle, "dlclose");
        local_dlerror = (unsigned long)dlsym(libdl_handle, "dlerror");
        dlclose(libdl_handle);
    }
    printf("[+] Local address: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",    
            local_dlopen, local_dlsym, local_dlclose, local_dlerror );  

  

    mmap_addr = get_remote_addr(target_pid, libc_path, (void *)local_mmap);    
    printf("[+] Remote mmap address: %x\n", mmap_addr);    
    
    /* call mmap */    
    parameters[0] = 0;  // addr    
    parameters[1] = 0x4000; // size    
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot    
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags    
    parameters[4] = 0; //fd    
    parameters[5] = 0; //offset    
    
    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)    
        goto exit;    
    
    //获取执行mmap函数的返回地址 也就是在目标进程分配内存的其实地址
    map_base = ptrace_retval(&regs);    


    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)local_dlopen );    
    dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)local_dlsym );    
    dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)local_dlclose );    
    dlerror_addr = get_remote_addr( target_pid, linker_path, (void *)local_dlerror );    
    

    printf("[+] remote address: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",    
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);    
    
   
    //将要注入的so路径写入到map_base内存  
    ptrace_writedata(target_pid, map_base+FUNCTION_NAME_ADDR_OFFSET, library_path, strlen(library_path) + 1);    
    
    parameters[0] = map_base+FUNCTION_NAME_ADDR_OFFSET;       
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;     
    
    //call dlopen
    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)    
        goto exit;    
    
    //获取dlopen("library so")后的句柄
    //到此 我们已经注入我们所需要的so 返回so句柄
    void * sohandle = ptrace_retval(&regs);    
    
      

    //hook_entry_addr = (void *)dlsym(sohandle, "hook_entry");
    ptrace_writedata(target_pid, map_base + FUNCTION_HOOK_ADDR_OFFSET, function_name, strlen(function_name) + 1);    
    parameters[0] = sohandle;       
    parameters[1] = map_base + FUNCTION_HOOK_ADDR_OFFSET;     
    
    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)    
        goto exit;    
    
    void * hook_entry_addr = ptrace_retval(&regs);    
    printf("[+] hook_entry_addr = %p\n", hook_entry_addr);    
    
       
    //等同于hook_entry_addr = (void *)hook_entry("i am a paramater");
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, strlen(param) + 1);    
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;      
  
    if (ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 1, &regs) == -1)    
        goto exit;        
    
    printf("Press enter to dlclose and detach\n"); 
    getchar();

        

    parameters[0] = sohandle; 
    if (ptrace_call_wrapper(target_pid, "dlclose", dlclose_addr, parameters, 1, &regs) == -1)    
        goto exit;    
    
    /* restore */    
    ptrace_setregs(target_pid, &original_regs);    
    ptrace_detach(target_pid);    
    ret = 0;    
    
exit:    
    return ret;    
}    
int find_pid_of(const char *process_name)    
{    
    int id;    
    int pid = -1;    
    DIR* dir;    
    FILE *fp;    
    char filename[32];    
    char cmdline[256];    
    struct dirent* entry;  
    
    if (process_name == NULL)    
        return -1;    
    
    dir = opendir("/proc");    
    if (dir == NULL)    
        return -1;    
    
    while((entry = readdir(dir)) != NULL) {    
       	if( strcmp(entry->d_name,".")==0 || strcmp(entry->d_name,"..")==0)
            	continue;
	if(DT_DIR!=entry->d_type)
		continue;
      	sprintf(filename,"/proc/%s/cmdline", entry->d_name);    
      	fp = fopen(filename,"r");    
      	if (fp) {    
		fgets(cmdline, sizeof(cmdline), fp);    
		fclose(fp);    
//		printf("%s\n",cmdline);
		if (strcmp(process_name, cmdline) == 0) {    
		    /* process found */    
		    printf("PID:  %s\n", entry->d_name); 		    
		    pid=atoi(entry->d_name); 
		    break; 
		 }    
       }       
    }    
    
    closedir(dir);    
    return pid;    
}    


int main(int argc, char* argv[]) 
{
    
    	int target_pid=-1;
        target_pid=atoi(argv[1]);
	   
/*
        printf("%d\n",argc);//格式化输出
        while(argc)//当(统计参数个数)
        printf("%s\n",argv[--argc]);//格式化输出
*/
    	if (-1 == target_pid) {  
        	printf("Can't find the process\n");  
        	return -1;  
    	}  
    	inject_remote_process(target_pid, "../injectso/libexample.so", "hook_entry",  "I'm parameter!", strlen("I'm parameter!")); 


    	return 0;  
}    
