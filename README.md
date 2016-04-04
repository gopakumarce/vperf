vperf
=====

Bandwidth / Performance testing similar to iperf

FAQ:
=====

What is vperf ?
=================

Its a small utility that tries to do something like iperf - measure the end to end bandwidth.
As for the name, its just a "v" instead of "i", thats all :)

Why not just use vperf ?
===========================

The reason why vperf was written was to try bandwidth testing using different protocols - like
UDP using linux kernel stack, UDP crafted inside vperf, GRE using linux stack (see section at 
the end on configuring GRE), GRE crafted inside vperf, and TCP crafted inside vperf. The way that
different service providers (comcast/verizon etc..) throttle different kinds of traffic is hard 
to tell, more like black magic. So we wanted to try the same test run over different protocols to
see the difference (if any) in throughput.

Reading and understanding iperf and modifying it would have been an option, but that was clearly
going to take more time than just write one real quick. And hence vperf.

What data does vperf provide ?
================================

Whatever is the protocol chosen, vperf just provides one data as of today - the number of packets
recieved in a one second interval on the reciever end. Reciever end prints that info and relays it
back to the sender, sender knows exactly how much it sent, so it also says how many packets were
sent in one second and how many actually reached the other end. The packet sizes are kept constant.
Might enhance this in future to add latency/jitter reporting etc..

Who can use vperf ?
=====================

Like iperf, vperf is a tool/utility mostly for people with some network knowledge. So its not a 
speedtest.com kind of utility that anyone can use. And of course like iperf here we need access to
two machines running Linux where we can run the sender and reciever

How do I compile vperf ?
===========================

The only machines we have tried vperf on are 12.04 Ubuntus. Though it should just work on any ubuntu 
or any linux distro. Just get the source code and type "make" and you get "vperf" binary in the same
directory, thats pretty much about it.

Will all the protocols work for me ?
=======================================

Thats an important question. Depending on what modem you have at home, some might not work ! For example
Netgear modems are known to not let GRE traffic pass through!! So if you have netgear wireless router
or wired router or a Netgear cable modem or a netgear Verizon FIOS modem, guaranteed GRE wont work.

I have even observed that the "crafted" TCP inside vperf doest work with my Netgear wired router at home.
But if I connect directly to my Motorolla comcast modem, the crafted TCP works just fine. I am guessing
thats more of a bug in my crafted TCP code than netgear, need to debug that (TODO)

As for GRE, if I hook up my sender linux box directly to the comcast modem it works, but be very careful
not to blast a lot of GRE packets. The comcast modem dies after a very few seconds (like 30 seconds) of 
blasted GRE traffic, and after that looks like comcast keeps my link down for like a good 5 minutes or so
as some kind of "punishment". So be wary of doing that on comcast link.

As for UDP, that works pretty well under all circumstances and with all boxes.

Why does vperf have a crafted TCP ? Why not use Linux TCP ?
===============================================================

Well, the goal as stated before was primarily to push a TON of packets, and hide them under different skins,
TCP being just one of the skins. If we use the Linux tcp stack, we will be subject to the usual slow start
and window reduction and retransmission etc.. as per TCP RFC, those wont allow us to just have a blast of
TCP going from sender to reciever. So the crafted TCP we have just does enough of the SYN/SYN-ACK to open
a session and make all the devices in the path to think its a "good" TCP session and let us through. After
that we dont really do any retransmission or window reduction etc.. We advertise a 1Gb window always and
we just ACK the largest sequence number recieved so far. Similarly while quitting the program we just send
the usual FIN/FIN-ACK etc.. so that the intermediate devices clean up the sessions properly and let us
recreate a new session the next time.

Notes about IP address and Mac address (--sip, --dip, --smac, --dmac)
=======================================================================

In the case of IP address, the "sip" (ie source ip) is always the IP address in the ifconfig output
of whatever interface is used. But the "dip" (ie dest ip) is always the **PUBLIC** IP of the destination, not
the ifconfig IP address because the ifconfig IP address is usually the NAT-ed ip address. This applies to all
the types of traffic mentioned below

In the case of mac-address, the smac is just the mac address shown in ifconfig for the interface that 
sends packets out. The dmac is the ARP result for the default route. So for example below, I have eth0 
as my interface connecting to internet

root:~# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         73.15.174.1     0.0.0.0         UG    2      0        0 eth0

My default route is 73.15.174.1

root:~# arp -a
IP address       HW type     Flags       HW address            Mask     Device
73.15.174.1      0x1         0x2         00:01:5c:65:46:46     *        eth0

And my mac address for 73.15.174.1 is 00:01:5c:65:46:46 and that should be my dmac
   

Why are mac addresses needed in case of "crafted" packet option ?
===================================================================

The reason is that for crafted packets, we bypass the Linux kernel protocol stack entirely. So we need to 
create the entire packet with all the L2 and L3 headers, so we need to provide all the information including
mac addresses

How to send UDP using the Linux UDP stack
=============================================

Reciever: ./vperf --mode server --proto udp --sip <reciever-ip> --dip <sender-ip>

Sender:   ./vperf --mode client --proto udp --sip <sender-ip> --dip <reciever-ip>

NOTE: See the section on Additional Options to see how to send Linux UDP packets over a Linux GRE interface.

How to send UDP using vperf crafted packets
=============================================

Reciever: ./vperf --mode server --proto rudp --sip <reciever-ip> --dip <sender-ip> --smac <reciever-mac> --dmac <sender-mac> --intf eth0

Sender:   ./vperf --mode client --proto rudp --sip <sender-ip> --dip <reciever-ip> --smac <sender-mac> --dmac <reciever-mac> --intf eth0

NOTE: eth0 is just as an example, use the correct interface you are connecting to internet with


How to send GRE using vperf crafted packets
=============================================

Reciever: ./vperf --mode server --proto gre --sip <reciever-ip> --dip <sender-ip> --smac <reciever-mac> --dmac <sender-mac> --intf eth0

Sender:   ./vperf --mode client --proto gre --sip <sender-ip> --dip <reciever-ip> --smac <sender-mac> --dmac <reciever-mac> --intf eth0

NOTE: eth0 is just as an example, use the correct interface you are connecting to internet with

How to send TCP using vperf crafted packets
=============================================

Reciever: ./vperf --mode server --proto tcp --sip <reciever-ip> --dip <sender-ip> --smac <reciever-mac> --dmac <sender-mac> --intf eth0

Sender:   ./vperf --mode client --proto tcp --sip <sender-ip> --dip <reciever-ip> --smac <sender-mac> --dmac <reciever-mac> --intf eth0

NOTE: eth0 is just as an example, use the correct interface you are connecting to internet with

Additional Options
====================

    --time  : By default the sender just sends for 5 seconds and exits (closes TCP sessions if proto is tcp). This is done because
              if someone is running this test on the sender logged in remotely, then this blast traffic can kick out the remote
              session and leave the person with no way to kill the blast. So to be safe, by default we send 5 seconds. If more time
              is needed use this option, but be careful about the above mentioned fact.

              NOTE: Sender only option

    --pps   : By default we send 2000 packets per second each of size 1300 bytes. This can increase the packets per second to larger/smaller
              values (packet size remains 1300)

              NOTE: Sender only option

    --bind  : The bind option lets us route the packet out of a specific interface, like a GRE tunnel. See the section at the end on
              howto configure a GRE tunnel on Linux. So if we specify the GRE Tunnel's tunnel IP address (not the local or remote IP, but
              the tunnel IP), then assuming we use the Linux UDP as protocol, the UDP packet will be GRE encapsulated by the Linux GRE stack

              NOTE: Sender option. Reciever can also choose to bind to a source IP if required, but not mandatory

    --port  : By default the port used is 21234 (UDP or TCP - crafted or Linux stack). Use this option to change the default port setting

              NOTE: Sender AND reciever needs to specify matching ports

    --sincr : By default we just send packets over one port. If you want to send packets in a round robin fashion over more than one port,
              specify the number of ports here. So for example if we say --sincr 2, then we will send packets over ports 21234, 21235 and 
              21236 in a round robin fashion

              NOTE: Sender AND reciever needs to specify matching increment range

    --sport : The source port to use to send TCP packets (not used in UDP case today). Also the source port is used only if --sincr is 0, 
              that is we dont want to use the port increment option

    --int   : By default, the --pps (packets per "second") value specified is traslated to a packets-per-millisecond value. If
              packets-per-millisecond is too large a granularity, we can change that by specifying a larger number here. For example if
              we specify 10 here, we will divide the --pps rate into a packets-per-10milliseconds value, that number is also displayed
              when vperf is started on the sender side.

              NOTE: Sender only option

    --win   : By default the reciever reports recieved packets every one second (1000 milliseconds). We can specify a different reporting
              interval in milliseconds here. So if we say 100 here, then reciever will report recieved packets every 100 milliseconds

    --nosyn : For TCP, when vperf is launched, it tries to initiate a SYN/SYN-ACK sequence. If we specify "1" here as an option, then 
              we wont do a SYN/SYN-ACK, we will just assume the session is already created on the boxes in between sender and reciever.

Terminating the program and Control-C behaviour
=================================================

Control-C is used to terminate the program, but it has some additional tricks built in

Sender:

First Control-C will stop the sending traffic

Second Control-C will start the traffic again (same session, no more syn/syn-ack or anything in case of tcp)

Third Control-C will stop the traffic and exit if protocol is not TCP. For TCP it will initiate FIN/FIN-ACK sequence
and exit only after all sessions are closed

Fourth Control-C will exit the session even if TCP sessions are not all closed

Reciever:

First Control-C will exit if not tcp. In case of tcp it will initiate FIN/FIN-ACKs and wait for all sessions to
be closed before exiting.

Second Control-C will exit even if TCP sessions are pending closure


Setting up GRE tunnel on Linux
=================================

*   modprobe ip_gre .. Standard ubuntu has ip_gre module by default, nothing to install

*   ip tunnel add tun1 mode gre remote 54.177.79.171 local 73.15.174.128 ttl 255
    ip link set tun1 up
    ip addr add 10.10.10.1/24 dev tun1 
   
    Here 73.15.174.128 is my comcast public IP, 54.177.79.171 is the remote server eth0 IP as shown in ifconfig
    And 10.10.10.1 is just a random tun1 tunneled IP address, so the remote server end using similar config can
    use for example 10.10.10.2. 

NOTE1: If you are using AWS for example, the ifconfig eth0 will show a different address than 54.177.79.171 ..
54.177.79.171 is one of their public IPs, and ifconfig eth0 will be a private IP. But when issuing the command
above on the remote server (which say is AWS), then use the "local" as the IP shown in ifconfig eth0 and NOT the
public IP 54.177.79.171

NOTE2: If the GRE tunnel is left idle for a while then the tunnel stops working for some reason,
maybe need to add some kind of keepalive ? So if it goes hung what can be done is "ip tunnel del tun1"
and recreate it on both ends

