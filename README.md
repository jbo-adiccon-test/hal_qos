# hal_qos
Use "cake" instead of htb prioritiy and class 

tc qdisc add dev erouter0 root cake bandwidth 25Mbit overhead 0 mpu 0 diffserv4 

parameters: 
- interface: erouter0 
- 
- bandwith:  <N> 
 
configuration with dmcli 
 
 dmcli eRT addtable Device.QoS.Queue.  
 dmcli eRT setv Device.QoS.Queue.1.Interface string "erouter0"  
 dmcli eRT setv Device.QoS.Queue.1.ShapingRate int 25  
 dmcli eRT setv Device.QoS.Queue.1.Enable bool true  
  
 This is simple code without any error procedures etc. 
