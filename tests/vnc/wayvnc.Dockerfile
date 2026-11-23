# wayvnc, the VNC server of current Raspberry Pi OS, on a headless sway desktop, set up like the Pi:
# a TLS certificate and a username and password checked by the system (pi / raspberry), on port 5900.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends sway wayvnc foot openssl libpam-modules libpam-runtime ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash pi && echo 'pi:raspberry' | chpasswd
USER pi
WORKDIR /home/pi
ENV XDG_RUNTIME_DIR=/tmp/xdg WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman
RUN openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -subj /CN=wayvnc -days 30 2>/dev/null \
 && mkdir -p .config/wayvnc \
 && printf 'address=0.0.0.0\nport=5900\nenable_auth=true\nenable_pam=true\nprivate_key_file=/home/pi/key.pem\ncertificate_file=/home/pi/cert.pem\n' > .config/wayvnc/config \
 && printf 'output HEADLESS-1 resolution 1024x768\nexec foot -e sh -c "echo wayvnc server; sleep 100000"\n' > sway.conf
COPY wayvnc-start.sh /home/pi/start.sh
CMD ["sh", "/home/pi/start.sh"]
