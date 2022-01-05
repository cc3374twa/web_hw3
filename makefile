all:
	gcc CheckPacket.c -o CheckPacket -lpcap
clean:
	rm CheckPacket
run:
	sudo ./CheckPackets
