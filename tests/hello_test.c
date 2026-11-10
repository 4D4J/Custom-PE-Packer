#include <stdio.h>

int main(void) {
    /* The packer looks for the literal "Hello from non-packed" in .rdata
       and tells the stub to overwrite it in memory with "Hello from packed"
       (space-padded to the exact same length). Running the raw binary
       prints "Hello from non-packed"; running the packed one prints
       "Hello from packed    " -- visual proof that the stub can patch
       arbitrary bytes inside the unpacked image at runtime. */
    puts("Hello from non-packed");
    (void)getchar();
    return 0;
}
