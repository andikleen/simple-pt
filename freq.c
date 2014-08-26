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
