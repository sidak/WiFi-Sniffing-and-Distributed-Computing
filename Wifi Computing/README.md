// if wlan1 is the interface through which we are sending/receiving of packets

sudo ifconfig wlan1 down
sudo iwconfig wlan1 mode monitor
sudo ifconfig wlan1 up
sudo iwconfig wlan1 chan 7

make

// For the client
sudo ./packetspammer wlan1 3+1 q

// For the server 
sudo ./packetreceiver wlan1 50

