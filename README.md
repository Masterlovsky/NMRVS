# NMRVS - SEANet

**Name Mapping Resolution Verification System** for **SEANet**

- *All right reserved by 3NMedia.*

## Description

> This project is made for verifying the **NMR** system

## How to use

- Firstly, you should install python3(ver>3.6). Then run the following command,

```shell
$ python3 -m pip install --upgrade pip
$ pip3 install -r requirement.txt
```

### 1. controller.py

```shell
# start the script:
$ python3 controller.py

# start some nodes you can tap in : 
start Node_1 Node_2 / start 1 2 / start 1-4

# kill some nodes you can tap in: 
kill Node_3 Node198 Node4 / kill 3 4 / kill 5-7

# stop some nodes you can tap in: 
stop Node_1 Node_2 / stop 1 2 3 4 / stop 1-4

# handle simulation nodes you can tap in:
s start Node_1 Node_2 / s start 1-2 / simulation stop 1-4

# If you have done all the control, input 'exit' or press the 'enter' button to stop the input process
exit
```

### 2. delay_gen.py

```shell
# start the script:
$ python3 delay_gen.py

# For example, create delay of two nodes you can tap in : 
Node_1 Node_2 <delay> or 1 2 <delay>

# Create delay of Simulation nodes, you can tap in:
s <Node_ID> <Node_level> <delay_l1> <delay_l2> <delay_l3>

# Create p2p delay of Simulation nodes, you can tap in:
s s <ID1-ID2> <delay>

# The first letter 's' can be replaced by 'S' or "simulation", Node_ID can be replaced by just ID(number)
# delay_l1~delay_l3 is the common delay of level1~3 nodes, these three parameter can be omitted, default is [100,50,10].
```

### 3. topologyCollector.py

```shell
# Before starting topology listening, you need to start mysql and create the "NMRVS" table in the database

# Run topo collector to collect topology information:

$ python3 topoCollector.py
```

### 4. topoShow.py

```shell
# Build the topology with the data in the current database and generate HTML files for presentation

# Run the following command:

$ python3 topoShow.py

# Open the generated HTML file to check the result
```

### 5. client.py

```shell
# The Simulated client write in Python.
# Used to send various UDP packets to the parsing node to verify the SEANet Resolution System.

# Run the following command：

$ python3 client.py -i <IP> -p <port> <...args...>
``` 

- 参数设定：

  **`-h`** : Open the help document  (optional)

  **`-i`** : Destination IP address to be sent. (support IPv4 and IPv6) **(mandatory)**

  **`-p`** : Destination port number，default is*10061*，this is the *Level1* listening port of ResNode **(mandatory)**

  **`-c`** : Convenient operation instruction which includes：

       register msg: 'r'
       register msg cid version: 'rcid'
       register msg cuckoo-filter version: 'rcc'
       deregister msg: 'd' 
       deregister msg cid version: 'dcid' 
       deregister msg cuckoo-filter version: 'dcc' 
       batch deregister: 'bd'
       resolve msg: 'eid', (default eid: "b"*40)
       resolve msg cid version: 'ecid', (default cid: "c"*64)
       resolve msg cuckoo-filter version: 'qcc', (default eid: "b"*40)
       tlv resolve msg: 'tlv', (default eid: "0"*40, default tlv: "010101020102")
       rnl request： 'rnl', to get RNL from a ResNode
       connect to agent: 'agent', Connect to the access agent to get RNL and other information.
       delay measure msg： 'dm', Tests the delay from the client to the resolution node
       user defined msg： 'custom' (default)，This parameter is usually used with the -m < MSG > parameter 

  **`-m`** : Enter the USER-DEFINED UDP payload of the complete packet

  **`-n`** : Number of packets to be sent. The default value is **1**. When 'n < 0', Client run in continuously mode.  

  **`-s`** : Set speed of packet sending (pps)，default: **no limit**，**need`-n=-1` and `--force` args**。

  **`--force`** : Sends a packet forcibly without waiting for response，usually combine with `-n`

  **`--detail`** : Parses returned packets and displays to users in a more detailed and clear manner.

  **`-er`** : Send the user-defined EID registration packet. TLV is optional, example: `-er  <EID+NA>  <tlv>`

  **`-ecr`** : Send the user-defined EID+CID register packet. TLV is optional, example:`-ecr <EID+CID+NA> <tlv>`

  **`-eq`** : Send the user-defined EID query packet, example:`-eq <EID> `

  **`-tq`** : Send the user-defined tag query packet, example:`-tq <tlv> `

  **`-ecq`** : Send the user-defined EID+CID query packet, there are two args. **queryType**_{**0**：EID->IP **1**：EID->CID **2**：CID->IP **3**：EID+CID->IP **4**：tag->EID+CID+IP, **5**：CID->EID}. Example: `-ecq <queryType> <EID>/<CID>/<TAG> `

  **`-ed`** : Send the user-defined EID deregister packet. example: `-ed <EID + NA> `

  **`-ecd`** : Send the user-defined EID+CID deregister packet, example: `-ecd <EID+CID+NA> `

  **`-ebd`** : Send the user-defined EID batch deregister packet, example: `-ebd <NA> `

  **`-ecbd`** : Send the user-defined EID+CID batch deregister packet, example:`-ebcd <NA> `
  
  **`-ccr`** : Send the user-defined CuckooRegister from self defined URI and NA,  use: `-ccr <uri ip> `
  
  **`-ccd`** : Send the user-defined CuckooDeregister from self defined URI and NA,  use: `-ccd <uri ip> `
  
  **`-ccq`** : Send the user-defined CuckooQuery from self defined URI,  use: `-ccq <uri> `
  
  **`--seq`** : Send a series of packets with EID from 0 to n. **need to use with`-n`parameter**，**only has effect in register**.

  **`--seqc`** : Send a series of packets with CID from 0 to n. **need to use with `-n`parameter**，**only has effect in register**，Can be used with --seq.

  **`--seqT`** : Send a series of packets with random TAG. **need to use with `-n`parameter**，**only has effect in register**，

  **`--seqt`** : Send a series of packets with fixed TAG.(010101020102)， **need to use with `-n`parameter**，**only has effect in register**，

  **`--ranReqID`** : Use random request ID.

  **`--ranAll`** : Use random possible fields(EID, CID, NA, ReqID, TLV, ...) when sending multiple message.
  
  **`-uh`** : Calculate SEAHash of custom defined URI to EID. Not sending messages.

### 6. pktAnalyzer.py

```shell
# This command is used to analyze captured PCAP files and view information about parsed packets, such as delay and timeout number.

# Run the following command：

$ python3 pktAnalyzer.py test.pcap <e/cc>
``` 
- e: EID mode
- cc: CuckooFilter mode
- default(without param 2): CID mode
- The time delay trend reference chart can be viewed in the generated 'len_delay.html' and the number of horizontal marks can be modified in the **'conf.yml'** configuration file
