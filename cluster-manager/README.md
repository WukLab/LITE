LITE's cluster manager source code is located in cluster-manager/, which runs on user space. Assume this machine has installed all IB user libraries, you can go to this directory and simply do make. After that, you will have a mgmt-server, which is LITE's clueter manager. Also, get the IP address of this CD server, which will be used by all other LITE clients to establish connection.


You can start cluster manager like this:

./mgmt-server
./mgmt-server -p [eth_port] -i [ib_port]

