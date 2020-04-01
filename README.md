# Network-wide heavy-hitter detection implementation in P4 language 
Citation
--------
```
@article{ding2020incrementally,
  title={An incrementally-deployable P4-enabled architecture for network-wide heavy-hitter detection},
  author={Ding, Damu and Savi, Marco and Antichi, Gianni and Siracusa, Domenico},
  journal={IEEE Transactions on Network and Service Management},
  year={2020},
  publisher={IEEE}
}
```
Installation
------------

1. Install [docker](https://docs.docker.com/engine/installation/) if you don't
   already have it.

2. Clone the repository to local 

    ```
    git clone https://github.com/DINGDAMU/Network-wide-heavy-hitter-detection
    ```

3. ```
    cd Network-wide-heavy-hitter-detection
   ```

4. If you want, put the `p4app` script somewhere in your path. For example:

    ```
    cp p4app /usr/local/bin
    ```
    I have already modified the default docker image to **dingdamu/p4app-ddos:nwhhd**, so `p4app` script can be used directly.

5.  ```
    ./p4app run nwhhd.p4app 
    ```
    After this step you'll see the terminal of **mininet**
6. Open a new terminal
   ```
    cd nwhhd.p4app 
   ```
7. Enter the terminal of Docker
   ```
    bash terminal.sh 
   ```
8. Activate interface veth0 to monitor all packets in the Network
   ```
    ip link add name veth0 type veth peer name veth1
    ip link set dev veth0 up
    ip link set dev veth1 up
   ```

9. Start controller in Docker 
   ```
    sudo python3 controller.py
   ```
10. Go back to **mininet** terminal and run following command within 5s (5s is the time interval) 
   We set 10 time intervals in this case
    ```
    pingall
   ```
11. Check the results of controller


