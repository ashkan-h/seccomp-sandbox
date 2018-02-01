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
	file_before_filter = open("testfile.txt", O_CREAT | O_EXCL | O_RDWR);
	int rc = 0;

	if(file_before_filter) {
		printf("Before Filter: testfile was openned successfully! Let's write something there \n");
		if(write(file_before_filter,"This will be output to testfile.txt \n", 36) != 36){
        	printf("There was an error writing to testfile.txt \n");    // strictly not an error, it is allowable for fewer characters than requested to be written.
        	return 1;
    	}
    	close(file_before_filter);	
	}

	else {
		printf("Failed opening the file even before filters. Exiting. \n");
		exit(0);
	}

	ctx = seccomp_init(SCMP_ACT_KILL);
	
	if (ctx == NULL) {
		printf("seccomp initilization failed\n");
		goto out;
	}

	rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

	if (rc != 0)
		goto out;

	rc = seccomp_load(ctx);
	
	if (rc < 0){
		goto out;
	}

	else {
		printf("seccomp loaded succefully! \n");
		printf("now will try again to open the testfile \n");
	}

	fd = open("testfile.txt", O_RDWR);
	if (fd >= 0){
		printf("error, was able to open?! \n");
	}
	else {
		printf("seccomp was succeful. open failed! \n");
		printf("open on fd %d returned errno %d\n", fd, errno);
	}

	close(fd);
	exit(0);
	
	out: 
		seccomp_release(ctx);
        printf("There was an error with seccomp! \n");
        return -rc;
}