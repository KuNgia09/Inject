linux x86 inject:
	targetprocess:被注入目标进程
	hijack:实现将Inject目录下的so注入
	Inject:被注入的so

usage:
	./hijack target_pid


FAQ:
1. mmap函数在libc-xxx库　而dlopen,dlsym等函数实在libdl库
   由于要在目标进程执行dlopen函数　，所以被注入进程需要加载libdl-xxx.so


参考资料：

