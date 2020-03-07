#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern char **environ;

int main() {
  
  char *args[] =
  {
    "/bin/sh", "-c",
    "/bin/ls", NULL
  };
  
  pid_t pid = fork();
  
  if(pid == 0) {
     /* child */
     printf("child\n");
     execve(args[0], &args[0], environ);
  }
  else if(pid > 0) {
     /* parent */
     printf("parent\n");
  }

  return 0; 
}
