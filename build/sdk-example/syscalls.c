/* newlib syscall shim for the MVsilicon B1 SDK (which targets Andes "mculib", not newlib).
 * stdout goes through the SDK's nds_write()/putchar() in startup/retarget.c.
 * Heap = [_end, _stack-STACK_RESERVE) from the SDK linker script; no files, no stdin.
 * Original code for this repo; not taken from the SDK. */
#include <errno.h>
#include <sys/stat.h>
#include <stddef.h>

#define STACK_RESERVE 0x800

extern void nds_write(const unsigned char *buf, int size);
extern char _end, _stack;

int _write(int fd, const char *buf, int n) { (void)fd; nds_write((const unsigned char *)buf, n); return n; }
int _read(int fd, char *buf, int n)        { (void)fd; (void)buf; (void)n; errno = EBADF; return -1; }
int _close(int fd)                         { (void)fd; errno = EBADF; return -1; }
int _lseek(int fd, int off, int whence)    { (void)fd; (void)off; (void)whence; return 0; }
int _isatty(int fd)                        { (void)fd; return 1; }
int _fstat(int fd, struct stat *st)        { (void)fd; st->st_mode = S_IFCHR; return 0; }

void *_sbrk(ptrdiff_t incr)
{
    static char *brk;
    char *limit = &_stack - STACK_RESERVE;
    if (!brk) brk = &_end;
    if (brk + incr > limit) { errno = ENOMEM; return (void *)-1; }
    char *prev = brk; brk += incr; return prev;
}
