# wayvnc, the VNC server of current Raspberry Pi OS, on a headless sway desktop, set up like the Pi:
# a TLS certificate and a username and password checked by the system (pi / raspberry), on port 5900.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends sway wayvnc foot openssl openssh-client libpam-modules libpam-runtime ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash pi && echo 'pi:raspberry' | chpasswd
USER pi
WORKDIR /home/pi
ENV XDG_RUNTIME_DIR=/tmp/xdg WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman
# The same files and settings as a Raspberry Pi OS Bookworm Pi: relative paths in /etc/wayvnc/config's folder, a TLS key
# and certificate, and an RSA key (which makes wayvnc offer RSA-AES as well, which WebTerm does not use).
RUN mkdir -p .config/wayvnc && cd .config/wayvnc \
 && openssl req -x509 -newkey rsa:2048 -nodes -keyout tls_key.pem -out tls_cert.pem -subj /CN=wayvnc -days 30 2>/dev/null \
 && ssh-keygen -m pem -t rsa -N "" -f rsa_key.pem >/dev/null \
 && printf 'use_relative_paths=true\naddress=::\nenable_auth=true\nenable_pam=true\nprivate_key_file=tls_key.pem\ncertificate_file=tls_cert.pem\nrsa_private_key_file=rsa_key.pem\n' > config \
 && cd /home/pi && printf 'output HEADLESS-1 resolution 1024x768\nexec foot -e sh -c "echo wayvnc server; sleep 100000"\n' > sway.conf
COPY wayvnc-start.sh /home/pi/start.sh
CMD ["sh", "/home/pi/start.sh"]
