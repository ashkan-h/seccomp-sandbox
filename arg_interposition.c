#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main()
{
	int file_before_filter;
	int fd;
	scmp_filter_ctx ctx;
	int rc = 0;

	file_before_filter = open("testfile3.txt", O_CREAT | O_EXCL | O_RDWR);
	if(file_before_filter) {
		printf("Before Filter: testfile3 was openned successfully! Let's write something there \n");
		if(write(file_before_filter,"This will be output to testfile3.txt \n", 37) != 37){
        	printf("There was an error writing to testfile.txt \n");    // strictly not an error, it is allowable for fewer characters than requested to be written.
        	return 1;
    	}
    	close(file_before_filter);	
	}

	ctx = seccomp_init(SCMP_ACT_KILL);

	if (ctx == NULL){
		printf("[X] FAILED: seccomp initilization failed\n");
		goto out;
	}

	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1,  SCMP_A1(SCMP_CMP_EQ, O_RDONLY));
	if (rc != 0)
		goto out;

	rc = seccomp_load(ctx);
	
	if (rc < 0){
		goto out;
	}

	else {
		printf("[*] seccomp rules were loaded succefully! \n");
	}

	fd = open("testfile3.txt", O_RDONLY);
	if (fd >= 0){
		printf("[*] Test passed. Open did NOT fail, because it's read only \n");
		close(fd);
	}	
	else {
		printf("open on fd %d returned errno %d\n", fd, errno);
		printf("[X] Test failed. Open should work since it's read only\n");
	}

	printf("Bad system call means the test has passed. Since the next call is open with read write! \n");
	fd = open("testfile3.txt", O_RDWR);
	if (fd >= 0){
		printf("[X] Test failed. Open on fd %d returned errno %d\n", fd, errno);
	}
	else {
			printf("[*] Test passed. Open failed with read write! \n");
		
	}

	out: 
		seccomp_release(ctx);
        printf("There was an error with seccomp! \n");
        return rc;
}