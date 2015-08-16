# tcp_dweet
Let's dweet! A simple TCP/IP stack (TCP client only) and a dweet.io demo application built on top
of my PIC32 framework.

This simple TCP client has been developed for establishing a connection with
dweet.io in order to exchange two values between a PIC32 Ethernet Starter Kit
and a personal tablet over the internet. So, a dedicated Android APP has been
developed.

For running a test just push switch button 2 (SW2) on the PIC32 Ethernet Starter
Kit for opening a connection with dweet.io and than send the following string
through a web browser:

http://dweet.io/dweet/for/%7Bprova_sens%7D?temp=alta&pioggia=nulla

the LED 1 will be turned ON. For turning it OFF send:

http://dweet.io/dweet/for/%7Bprova_sens%7D?temp=bassa&pioggia=nulla

when you prefer. Finally, for closing the established connection click SW2
again.
The refresh time could be configured as all other parameters.

This project is just an IoT "experiment" so your help is appreciate!

Known issues:
- Ethernet layer remains stacked until an Ethernet cable is connected. It is necessary to add a timeout in order to exit the related infinite loop in eth.c file.
- Sometime connection is not closed successfully: final ACK is not sent.
