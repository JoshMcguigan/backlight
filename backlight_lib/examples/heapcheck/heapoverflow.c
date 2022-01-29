// Copyright © 2019 by Dennis Andriesse.
//
// This example comes from chapter 7 of the "Practical Binary Analysis" book.
//
// A copy of this source code can be downloaded from the authors website:
// https://practicalbinaryanalysis.com/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char *argv[])
{
  char *buf;
  unsigned long len;

  if(argc != 3) {
    printf("Usage: %s <len> <string>\n", argv[0]);
    return 1;
  }

  len = strtoul(argv[1], NULL, 0);
  printf("Allocating %lu bytes\n", len);
  buf = malloc(len);

  if(buf && len > 0) {
    memset(buf, 0, len);

    strcpy(buf, argv[2]);
    printf("%s\n", buf);

    free(buf);
  }

  return 0;
}
