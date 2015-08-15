
volatile int v;

int main(void)
{
	int i;

	prctl(12341234); /* marker 1 */
	for (i = 0; i < 100; i++)
		v++;
	write(1, "foo\n", 4);
	personality(21212212); /* marker 2 */
	return 0;
}
