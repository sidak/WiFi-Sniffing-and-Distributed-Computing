all: packetspammer packetreceiver
packetspammer: packetspammer.c
	gcc  -Wall radiotap.c packetspammer.c -o packetspammer -lpcap
packetreceiver: packetreceiver.c
	gcc  -Wall radiotap.c packetreceiver.c -o packetreceiver -lpcap -lm

