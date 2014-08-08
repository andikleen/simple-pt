#!/usr/bin/perl -p
# print usec time deltas
# ptdump file | ./timedelta.pl 

# XXX
$freq=2.4;

if (/tsc/) {
	@n=split;
	printf "%.6f\t", (hex($n[2]) - hex($prev)) / (1000000*$freq);
	$prev = $n[2];
} else { 
	print "\t\t";
} 
