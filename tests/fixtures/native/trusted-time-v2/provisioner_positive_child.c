#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

int
main(void)
{
    static const unsigned char seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    size_t offset = 0U;

    errno = 0;
    if (fork() != (pid_t)-1 || errno != EPERM) {
        return 2;
    }
    while (offset < sizeof(seed)) {
        ssize_t written = write(STDOUT_FILENO, seed + offset, sizeof(seed) - offset);
        if (written <= 0) {
            return 1;
        }
        offset += (size_t)written;
    }
    return 0;
}
