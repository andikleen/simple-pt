/* Query P1 CPU frequency */
/*
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

double get_freq(void)
{
     FILE *f = fopen("/proc/cpuinfo", "r");
     if (!f)
	  goto fallback;

     char *line = NULL;
     size_t linelen = 0;
     double frequency = 0;
     while (getline(&line, &linelen, f) > 0) {
	  char unit[10];

	  if (strncmp(line, "model name", sizeof("model name")-1))
	       continue;
	  if (sscanf(line + strcspn(line, "@") + 1, "%lf%10s", 
		     &frequency, unit) == 2) {
	       if (!strcasecmp(unit, "GHz"))
		    ;
	       else if (!strcasecmp(unit, "Mhz"))
		    frequency *= 1000;
	       else {
		    printf("Cannot parse unit %s\n", unit);
		    goto fallback;
	       }
	       break;
	  }
     }     
     free(line);
     fclose(f);
     if (frequency)
	  return frequency;
    
fallback:
     f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", "r");
     int found = 0;
     if (f) {
         found = fscanf(f, "%lf", &frequency);
	 fclose(f);
     }
     if (found == 1) {
         frequency /= 1000000.0;
         return frequency;
     }
     return 0;
}
