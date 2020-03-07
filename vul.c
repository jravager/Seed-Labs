#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
void main()
{
    setuid(geteuid()); // make real uid = effective uid.
    system("/bin/ls -l");
}
