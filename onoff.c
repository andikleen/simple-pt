/* Demonstrate how to enable/disable simple-pt from a program */
#include <stdio.h>
#include <sys/fcntl.h>
#include <unistd.h>

#define noinline __attribute__((noinline))

volatile int v;

void sptcmd(int flag, char *fn)
{
	char buf[10];
	int len = snprintf(buf, sizeof buf, "%d\n", flag);
	int fd = open(fn, O_WRONLY);
	if (fd >= 0) {
		write(fd, buf, len);
		close(fd);
	}
}

void onoff(int flag)
{
	sptcmd(flag, "/sys/module/simple_pt/parameters/start");
}

void disable_clear(void)
{
	sptcmd(0, "/sys/module/simple_pt/parameters/clear_on_start");
}

noinline void f1(void)
{
	int i;
	for (i = 0; i < 100; i++)
		v++;
}

noinline void f2(void)
{
	int i;
	for (i = 0; i < 100; i++)
		v++;
}

noinline void f3(void)
{
	int i;
	for (i = 0; i < 100; i++)
		v++;
}

int main(void)
{
	onoff(1);
	/* Disable clear on start */
	disable_clear();
	f1();
	write(1, "foo\n", 4);
	onoff(0);
	f2();
	write(1, "xyz\n", 4);
	onoff(1);
	f3();
	write(1, "bar\n", 4);
	onoff(0);
	return 0;
}
