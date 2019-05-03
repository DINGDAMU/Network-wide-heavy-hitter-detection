# Implementing Network-wide heavy-hitter detection in P4 language 


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
    I have already modified the default docker image to **dingdamu/p4app-ddos**, so `p4app` script can be used directly.

5.  ```
    p4app run nwhhd.p4app 
    ```
    After this step you'll see the terminal of **mininet**
6. ```
    cd nwhhd.p4app 
   ```
7. Enter the terminal of Docker
   ```
    bash terminal.sh 
   ```
8. Start controller in Docker 
   ```
    sudo python3 controller.py
   ```
9. Go back to **mininet** terminal and run following command within 5s (5s is the time interval) 
    ```
    pingall
   ```
10. Check the results of controller


