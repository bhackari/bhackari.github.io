---
date: '2024-04-19T12:00:00Z'
draft: false
title: 'Tulip setup for A/D CTFs'
summary: "Tulip is a traffic analyzer tool made for A/D CTFs, this post walks you throught all the important steps requied to deploy Tulip painlessly (hopefully)."

categories: 
    - docs
keywords: 
    - attack-defense
    - infra
author: bhackari
---

# Setup tulip on the VM

### Tulip specific configurations

Clone the repo
```
$ git clone https://github.com/OpenAttackDefenseTools/tulip.git  
$ cd tulip  
```

---

Edit `services/api/configurations.py` with the correct `tick_length`, `start_date`, `vm_ip`, and the `services`  

---

```
$ cp .env.example .env  
```

edit `.env` with the correct `FLAG_REGEX`, `TICK_START`, `TICK_LENGTH` and 
change `TRAFFIC_DIR_HOST` to point to the correct folder containing the pcaps (in our case `/ready_pcaps`)

---

If you want tulip to listen on a different port (e.g. port 4444) edit `docker-compose.yml` 
and under the `frontend` service change 
```yml
ports: 
    - "3000:3000"
```
to
```yml
ports: 
    - "4444:3000"
```

**WARNING:**
(if you host tulip on the vulnbox and don't change the web interface port you risk other teams to steal flags throght tulip. Yep, they know tulip default port is 3000)

---

```
$ docker compose up -d --build
```

Tulip is now running.

---

### Packet capturing

Save these scripts:  

`/create-pcap.sh`
```bash
#!/bin/sh
# -i game : game is the wireguard network interface, change it as needed

mkdir -p /pcaps
mkdir -p /ready_pcaps
chmod 777 /pcaps
chmod 777 /ready_pcaps

tcpdump -G 120 -w /pcaps/myfile-%Y-%m-%d_%H.%M.%S.pcap -i game -z '/post-rotate.sh' port not 22
```

`/post-rotate.sh`
```bash
#!/bin/sh
mkdir -p /ready_pcaps/
mv $1 /ready_pcaps/
```

Then disable the apparmor profile for tcpdump
```
$ apt install apparmor-utils
$ aa-complain /usr/bin/tcpdump
```

Now in a tmux or screen:
```
$ chmod +x /create-pcap.sh
$ chmod +x /post-rotate.sh
$ /create-pcap.sh
```

While `create-pcap.sh` is running, `ready_pcaps` will be populated with the network pcaps and 
Tulip will show them on the web interface.s

---
# Setup Tulip on a dedicated VPS

## On the vps

Clone the repo
```
$ git clone https://github.com/OpenAttackDefenseTools/tulip.git  
$ cd tulip  
```

---

Edit `services/api/configurations.py` with the correct `tick_length`, `start_date`, `vm_ip`, and the `services`  

---

```
$ cp .env.example .env  
```

edit `.env` with the correct `FLAG_REGEX`, `TICK_START` and `TICK_LENGTH`

---

If you want tulip to only listen on `localhost:3000` instead of `0.0.0.0:3000`, then edit `docker-compose.yml` 
and under the `frontend` service change 
```yml
ports: 
    - "3000:3000"
```
to
```yml
ports: 
    - "127.0.0.1:3000:3000"
```

---

```
$ docker compose up -d --build
```

Tulip is now running.

---

## On the vulnbox

Save these scripts:  

`/create-pcap.sh`
```bash
#!/bin/sh
# -i game : game is the wireguard network interface, change it as needed

mkdir -p /pcaps
mkdir -p /ready_pcaps
chmod 777 /pcaps
chmod 777 /ready_pcaps

tcpdump -G 120 -w /pcaps/myfile-%Y-%m-%d_%H.%M.%S.pcap -i game -z '/post-rotate.sh' port not 22
```

`/post-rotate.sh`
```bash
#!/bin/sh
mkdir -p /ready_pcaps/
mv $1 /ready_pcaps/
```

Then disable the apparmor profile for tcpdump
```
$ apt install apparmor-utils
$ aa-complain /usr/bin/tcpdump
```

Now in a tmux or screen:
```
$ chmod +x /create-pcap.sh
$ chmod +x /post-rotate.sh
$ /create-pcap.sh
```

While `create-pcap.sh` is running, `ready_pcaps` will be populated with the network pcaps.

---

## Send pcaps to tulip

The last thing is to send the pcaps to tulip, there are two ways to do it :
- 1: The vps has ssh access to the vulnbox, and can scp the pcaps
- 2: The vps is not in the vpn, so no access to the vulnbox. In this case the vulnbox will have ssh access to the vps (this could be hardened)

---

### `Case 1`:  
First create an ssh key in the vps and add it in the vulbox.  
Then, on the vps save the script `take-pcap.sh`:
```bash
#!/usr/bin/bash

IP_VULNBOX=10.32.55.2

while true
do
	rsync -avz --remove-source-files root@$IP_VULNBOX:/ready_pcaps/* CHANGE_ME_TRAFFIC_DIR_HOST
	sleep 10 # tweak this as you like
done
```

Now open a tmux and run this script, tulip will receive the pcaps.

---

### `Case 2`:
First create an ssh key in the vulnbox and add it in the vps.  
Then, on the vulnbox save the script `take-pcap.sh`:  
```bash
#!/usr/bin/bash

IP_VPS=10.32.55.2 # remember to change this

while true
do
	rsync -avz --remove-source-files /ready_pcaps/* root@$IP_VPS:CHANGE_ME_TRAFFIC_DIR_HOST
	sleep 10 # tweak this as you like
done
```

Now open a tmux and run this script, tulip will receive the pcaps.

---

`CHANGE_ME_TRAFFIC_DIR_HOST` is the absolute path to the `TRAFFIC_DIR_HOST` value in the `.env` you wrote when configuring tulip.