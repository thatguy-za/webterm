#!/bin/sh
Xvnc :1 -rfbport 5900 -SecurityTypes VncAuth -PasswordFile /home/pi/.vnc/passwd -geometry 1024x768 -depth 24 &
Xvnc :2 -rfbport 5901 -SecurityTypes X509Plain -X509Cert /home/pi/.vnc/cert.pem -X509Key /home/pi/.vnc/key.pem -PlainUsers pi -geometry 800x600 -depth 24 &
sleep 2
DISPLAY=:1 xterm -geometry 60x12+20+20 -e 'echo VNC password server; sleep 100000' &
DISPLAY=:2 xterm -geometry 60x12+20+20 -e 'echo TLS login server; sleep 100000' &
wait
