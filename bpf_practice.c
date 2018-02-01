#include <linux/audit.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>


int main() {

	int file_before_filter;
	int fd;
	struct sock_fprog program;
	struct sock_filter filter[] = {
		   BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
		   BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0),	
		   BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
		   BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
		   BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 0, 1),
  	       BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  		   BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 0, 1),
  		   BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  		   BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_close, 0, 1),
  		   BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  		   BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)

	};

	file_before_filter = open("testfile2.txt", O_CREAT | O_EXCL | O_RDWR);
	
	if(file_before_filter) {
		printf("Before Filter: testfile2 was openned successfully! Let's write something there \n");
		if(write(file_before_filter,"This will be output to testfile2.txt \n", 37) != 37){
        	printf("There was an error writing to testfile.txt \n");    // strictly not an error, it is allowable for fewer characters than requested to be written.
        	return 1;
    	}
    	close(file_before_filter);	
	}

	else {
		printf("Failed opening the file even before filters. Exiting. \n");
		exit(0);
	}

	program.filter = filter;
	program.len = sizeof(filter) / sizeof(struct sock_filter);

  	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    	perror("prctl NO_NEW_PRIVS failed \n");
    	return 1;
  	}
  	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) {
    	printf("prctl failed ! \n");
    	return 1;
  	}

  	printf("BPF with the rules are all set and prctl succeeded! \n");
  	printf("Calling open to check the rules \n");
	
	fd = open("testfile2.txt", O_RDWR);

	if (fd >= 0){
		printf("Error, was able to open even with seccomp!?! \n");
	}
	else {
		printf("BPF rules were successful. open failed! \n");
		printf("open on fd %d returned errno %d \n", fd, errno);
	}

	close(fd);
	return 0;
}