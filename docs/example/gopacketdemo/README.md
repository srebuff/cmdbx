## network traffic statstic 


### kernel < 4.4

> AF_PACKET + MMAP

> The ithub.com/google/gopacket/afpacket package in gopacket uses the Linux-specific PACKET_MMAP feature to read packets directly from a shared memory ring


### for kernel >= 4.4

> use 