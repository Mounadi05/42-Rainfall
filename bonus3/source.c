#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned char byte;

int main(int argc, char **argv)

{
  int iVar1;
  char *puVar2;
  byte bVar3;
  char local_98[16];
  char local_57;
  char local_56[66];
  FILE *local_14;

  bVar3 = 0;
  local_14 = fopen("/home/user/end/.pass", "r");
  puVar2 = local_98;
  for (iVar1 = 0x21; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + (uint)bVar3 * -2 + 1;
  }
  if ((local_14 == (FILE *)0x0) || (argc != 2)) {
    iVar1 = -1;
  } else {
    fread(local_98, 1, 0x42, local_14);
    local_57 = 0;
    iVar1 = atoi(argv[1]);
    *(char *)(local_98 + iVar1) = 0;
    fread(local_56, 1, 0x41, local_14);
    fclose(local_14);
    iVar1 = strcmp((char *)local_98, argv[1]);
    if (iVar1 == 0) {
      execl("/bin/sh", "sh", 0);
    } else {
      puts(local_56);
    }
    iVar1 = 0;
  }
  return iVar1;
}
