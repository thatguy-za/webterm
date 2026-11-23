# TigerVNC servers for testing the VNC login, each with an xterm on its screen:
#   port 5900  a plain VNC password (raspberry)
#   port 5901  a TLS login with a username and password (pi / raspberry), as wayvnc offers
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends tigervnc-standalone-server tigervnc-tools xterm openssl ca-certificates libpam-modules libpam-runtime \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash pi && echo 'pi:raspberry' | chpasswd
USER pi
WORKDIR /home/pi
RUN mkdir -p .vnc && echo raspberry | vncpasswd -f > .vnc/passwd && chmod 600 .vnc/passwd \
 && openssl req -x509 -newkey rsa:2048 -nodes -keyout .vnc/key.pem -out .vnc/cert.pem -subj /CN=tigervnc -days 30 2>/dev/null
COPY tigervnc-start.sh /home/pi/start.sh
CMD ["sh", "/home/pi/start.sh"]
