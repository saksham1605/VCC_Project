#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include<errno.h>

#define DEVICE "/dev/ioctl_device"
#define IOCTL_GET_PHYS_ADDR _IOR(100, 0, unsigned long)
#define IOCTL_WRITE_VAL_AT_ADDR _IOW(100, 1, unsigned long[2])

int main() {
    int device = open(DEVICE, O_RDWR);
    if (device < 0) {
        perror("Failed to open the device");
        return errno;
    }

    // Allocate a byte-size memory
    unsigned long *data = (unsigned long *)malloc(sizeof(char));
    *data = 6; // Assign the value '6'

    // Print virtual address and value
    printf("Virtual Address: %lu, Value: %d\n", data, *data);

    // // Get physical address
    unsigned long phys_addr;
    // unsigned long a=10;
    if(ioctl(device, IOCTL_GET_PHYS_ADDR, data)==-1)
        printf("IOCTL ERROR");
    phys_addr=*data;
    printf("Physical Address: %lu\n", phys_addr);
    unsigned long write_args[2] = {(unsigned long)data, 5};
    ioctl(device, IOCTL_WRITE_VAL_AT_ADDR, write_args);

    // Verify the modified value
    printf("Modified Value: %d\n", *data);

    free(data);
    close(device);
    return 0;
}
