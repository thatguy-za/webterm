#!/bin/sh
mkdir -p "$XDG_RUNTIME_DIR" && chmod 700 "$XDG_RUNTIME_DIR"
sway -c /home/pi/sway.conf &
sleep 4
export WAYLAND_DISPLAY=wayland-1
exec wayvnc --output=HEADLESS-1 --log-level=debug
