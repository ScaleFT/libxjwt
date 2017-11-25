/**
 * Copyright 2017, ScaleFT Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "xjwt_tests.h"
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char executable_path[PATHMAX] = {'\0'};
char testdir_path[PATHMAX] = {'\0'};

#ifdef __APPLE__
#include <mach-o/dyld.h> /* _NSGetExecutablePath */
#endif

static void get_executable_path() {
#if defined(__APPLE__)
  uint32_t bufsize = sizeof(executable_path);
  _NSGetExecutablePath(executable_path, &bufsize);
#elif defined(__linux__)
  readlink("/proc/self/exe", executable_path, PATHMAX - 1);
#elif defined(__FreeBSD__)
  size_t cb = sizeof(executable_path);
  int mib[4];

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = -1;

  sysctl(mib, 4, executable_path, &cb, NULL, 0);
#else
#error port get_executable_path()
#endif
}

void xjwt_tests_setup() {
  char *p;
  get_executable_path();
  p = strrchr(executable_path, '/');
  memcpy(testdir_path, executable_path, p - executable_path);
}

void xjwt_load_fixture(const char *fname, char **outbuf, size_t *outlen) {
  char p[PATHMAX];
  FILE *fp;
  struct stat s;
  char *buf;

  snprintf(p, sizeof(p), "%s/../../../tests/fixtures/%s", testdir_path, fname);

  /* fprintf(stderr, "xjwt_load_fixture path: %s\n", p); */

  fp = fopen(p, "r");

  XJWT_ASSERT(fp != NULL);

  stat(p, &s);

  buf = malloc(s.st_size + 1);

  fread(buf, s.st_size, 1, fp);

  buf[s.st_size] = '\0';

  fclose(fp);

  *outbuf = buf;
  *outlen = s.st_size;
}
