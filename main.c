#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/sendfile.h>
#include <linux/memfd.h>

#define LXC_MEMFD_REXEC_SEALS (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif

/* Maximum number of bytes sendfile() is able to send in one go. */
#define LXC_SENDFILE_MAX 0x7ffff000

/**
 * Checks if we are already running from memfd. Returns 0 if not
 */
static int is_memfd(void)
{
	int fd, saved_errno, seals;

	fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -ENOTRECOVERABLE;

	seals = fcntl(fd, F_GET_SEALS);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	if (seals < 0)
		return -EINVAL;

	return seals == LXC_MEMFD_REXEC_SEALS;
}

#ifndef HAVE_MEMFD_CREATE
static inline int memfd_create(const char *name, unsigned int flags) {
	#ifndef __NR_memfd_create
		#if defined __i386__
			#define __NR_memfd_create 356
		#elif defined __x86_64__
			#define __NR_memfd_create 319
		#elif defined __arm__
			#define __NR_memfd_create 385
		#elif defined __aarch64__
			#define __NR_memfd_create 279
		#elif defined __s390__
			#define __NR_memfd_create 350
		#elif defined __powerpc__
			#define __NR_memfd_create 360
		#elif defined __sparc__
			#define __NR_memfd_create 348
		#elif defined __blackfin__
			#define __NR_memfd_create 390
		#elif defined __ia64__
			#define __NR_memfd_create 1340
		#elif defined _MIPS_SIM
			#if _MIPS_SIM == _MIPS_SIM_ABI32
				#define __NR_memfd_create 4354
			#endif
			#if _MIPS_SIM == _MIPS_SIM_NABI32
				#define __NR_memfd_create 6318
			#endif
			#if _MIPS_SIM == _MIPS_SIM_ABI64
				#define __NR_memfd_create 5314
			#endif
		#endif
	#endif
	#ifdef __NR_memfd_create
	return syscall(__NR_memfd_create, name, flags);
	#else
	errno = ENOSYS;
	return -1;
	#endif
}
#else
extern int memfd_create(const char *name, unsigned int flags);
#endif

ssize_t lxc_sendfile_nointr(int out_fd, int in_fd, off_t *offset, size_t count)
{
	ssize_t ret;

again:
	ret = sendfile(out_fd, in_fd, offset, count);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	return ret;
}

static void lxc_rexec_as_memfd(char **argv, char **envp, const char *memfd_name)
{
	int saved_errno;
	ssize_t bytes_sent;
	int fd = -1, memfd = -1;

	memfd = memfd_create(memfd_name, MFD_ALLOW_SEALING | MFD_CLOEXEC);
	if (memfd < 0)
		return;

	fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto on_error;

	/* sendfile() handles up to 2GB. */
	bytes_sent = lxc_sendfile_nointr(memfd, fd, NULL, LXC_SENDFILE_MAX);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	if (bytes_sent < 0)
		goto on_error;

	if (fcntl(memfd, F_ADD_SEALS, LXC_MEMFD_REXEC_SEALS))
		goto on_error;

	fexecve(memfd, argv, envp);

on_error:
	saved_errno = errno;
	close(memfd);
	errno = saved_errno;
}

static int lxc_rexec(const char *memfd_name, char **argv, char **envp)
{
	int ret;

	ret = is_memfd();
	if (ret < 0 && ret == -ENOTRECOVERABLE) {
		fprintf(stderr,
			"%s - Failed to determine whether this is a memfd\n",
			strerror(errno));
		return -1;
	} else if (ret > 0) {
        puts("Hello from rexeced memfd!\n");
		return 0;
	}

	lxc_rexec_as_memfd(argv, envp, memfd_name);
	fprintf(stderr, "%s - Failed to rexec as memfd\n", strerror(errno));
	return -1;
}

/**
 * This function will copy any binary that calls liblxc into a memory file and
 * will use the memfd to rexecute the binary. This is done to prevent attacks
 * through the /proc/self/exe symlink to corrupt the host binary when host and
 * container are in the same user namespace or have set up an identity id
 * mapping: CVE-2019-5736.
 */
static void liblxc_rexec(char **argv, char **envp)
{
	if (lxc_rexec("liblxc", argv, envp)) {
		fprintf(stderr, "Failed to re-execute liblxc via memory file descriptor\n");
		_exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv, char **envp)
{
    puts("Hello, World!");
    
    // execve: The argv and envp arrays must each include a null pointer
    //   at the end of the array.
    // duplicate mem for argv, ensuring it ends in NULL string
    char **argv_ = (char **)malloc((argc + 1) * sizeof(char *));
    argv_[0] = strdup(argv[0]);
    argv_[1] = NULL;
    
    liblxc_rexec(argv_, envp);
    return 0;
}
