# SOC Home Lab Setup

I built this lab to get hands-on experience with the kind of work SOC analysts do day to day. The setup is pretty simple: Kali Linux generates attack traffic, Security Onion captures and analyzes it, and I go through the alerts like an analyst would.

This document is mostly for my own reference but also for anyone who wants to build something similar. I ran into a few problems during setup that cost me a lot of time, so I wrote those down too.

---

## Lab Components

| Component | Details |
|---|---|
| Hypervisor | VirtualBox 7.2.4 |
| SIEM / IDS | Security Onion 2.4.211 |
| Attack machine | Kali Linux |
| Host RAM | 16 GB |

Security Onion gets 10 GB of that RAM. It needs at least 8 GB to run, but 10 GB is noticeably more stable on first boot.

---

## Network Layout

Three separate networks handle different types of traffic.

**Host-Only (192.168.56.0/24)** is the management network. The Security Onion web UI is here, SSH access goes through here, and the host machine connects to the VMs through this.

**Internal Network "soclab"** is where the actual lab traffic flows. Kali sends attack traffic into this network and Security Onion monitors everything passing through it.

**NAT** gives both VMs internet access. Nothing from the outside can reach the VMs through NAT, so this is safe to leave on.

| Machine | Interface | Network | IP |
|---|---|---|---|
| Security Onion | enp0s3 | Host-Only | 192.168.56.103 |
| Security Onion | enp0s8 | soclab | monitor only |
| Security Onion | enp0s9 | NAT | DHCP |
| Kali Linux | eth0 | NAT | DHCP |
| Kali Linux | eth1 | soclab | 192.168.100.10 |

---

## VirtualBox Setup

Before creating the VMs, go to File > Tools > Network Manager > Host-only Networks and check the Host-Only adapter.

It should show 192.168.56.1/24 with DHCP disabled. DHCP needs to be off because Security Onion gets a static IP during installation.

---

## Security Onion VM

Create the VM with these settings:

| Setting | Value |
|---|---|
| RAM | 10240 MB |
| CPU | 4 cores |
| Disk | 200 GB |

I gave Security Onion 200 GB of disk. This is actually the official minimum. it splits into 100 GB for /nsm (logs and PCAPs) and 100 GB for the rest of the system. In practice the lab ran fine with this, but more disk means longer log retention.

Then configure the adapters like this:

| Adapter | Type | Promiscuous Mode |
|---|---|---|
| Adapter 1 | Host-Only | Deny |
| Adapter 2 | Internal Network "soclab" | Allow All |
| Adapter 3 | NAT | Deny |

The adapter order is important. Security Onion's installer picks the first adapter as the management interface by default. Putting Host-Only as Adapter 1 means the management IP and web UI certificate end up on 192.168.56.103, which is what we want.

Adapter 2 needs Promiscuous Mode set to Allow All. Without this, Security Onion only sees traffic addressed to itself and misses everything else on the soclab network.

---

## Installing Security Onion

Boot from the ISO and go through the setup wizard. These are the screens that actually matter:

**Deployment type:** EVAL. Runs everything on one machine, which is fine for a home lab.

**Airgap:** Yes. The installer couldn't reach the internet during my setup, so I used airgap mode which installs everything from the ISO.

**Management interface:** enp0s3. To confirm this is the right one, compare the MAC address shown in the installer against the MAC address shown for Adapter 1 in VirtualBox.

**IP address:** 192.168.56.103/24, gateway 192.168.56.1, DNS 8.8.8.8 and 8.8.4.4.

**Monitor interface:** enp0s8. This is the soclab adapter. Suricata and Zeek will watch everything on this interface.

**Allowed subnet:** 192.168.56.0/24. Only machines in this range can access the web UI.

Installation takes around 20-30 minutes. The VM reboots automatically when it's done.

---

## After Installation

Log in and check that everything is running:

```bash
sudo so-status
```

The first boot is slow because Security Onion starts about 20 Docker containers in sequence. Give it 10-15 minutes before worrying. When everything is up, the output ends with:

```
This onion is ready to make your adversaries cry!
```

---

## Accessing the Lab

Web interface:
```
https://192.168.56.103
```

The browser will warn about the certificate. Security Onion uses a self-signed cert, so just click through the warning.

SSH from Windows gives you a proper terminal where you can paste commands and scroll through output comfortably. Working directly in the VirtualBox window is painful copy paste doesn't work well and the keyboard layout causes issues.

SSH from Windows:
```bash
ssh your-username@192.168.56.103
```

---

## Kali Setup

Assign an IP to the soclab interface so attack traffic goes through the monitored network:

```bash
sudo ip addr add 192.168.100.10/24 dev eth1
sudo ip link set eth1 up
```

On Security Onion, give the bond0 interface an IP on the same subnet:

```bash
sudo ip addr add 192.168.100.20/24 dev bond0
```

Note: these commands don't survive a reboot. You'll need to run them again each time you start the lab.

After this, running nmap against 192.168.100.20 sends traffic through soclab, and Security Onion captures it.

---

## Problems I Ran Into

**Web UI was completely unreachable after the first install**

My first attempt had Adapter 1 set to NAT instead of Host-Only. The installer picked that as the management interface and assigned 10.0.2.15 as the management IP. All the TLS certificates got generated for that address. Since the host machine can't reach the NAT network directly, the web UI was just gone. I had to reinstall from scratch with the adapters in the right order.

**Everything was extremely slow on first boot**

With 8 GB RAM, memory usage hit around 84% while services were starting up and things took forever. Bumping Security Onion to 10 GB fixed it.

**VirtualBox crashed when the VM rebooted after installation**

VirtualBox threw a Guru Meditation error right when the VM was rebooting at the end of installation. I just powered the VM off from VirtualBox and started it again manually. The installation was completely fine, it just didn't reboot cleanly.
