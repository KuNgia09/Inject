#include<stdio.h>
#include<unistd.h>
#include<dlfcn.h>
int main()
{
	int i;
	void* handle;
	handle=dlopen("libdl-2.19.so",RTLD_LAZY);
	for(i=0;i<10000;i++)
	{
		printf("[+]---call process %d\n",i);
		i++;
		sleep(3);
	}
}
