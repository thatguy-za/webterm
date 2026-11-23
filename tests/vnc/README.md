# VNC tests

`./run.sh` opens real VNC servers through WebTerm in headless Chromium and checks that each login works end to end, with
the remote screen drawn in the page. It starts two images built from the Dockerfiles here:

- `tigervnc.Dockerfile`: TigerVNC with a plain VNC password (port 5900) and a TLS login with a username and password (port 5901).
- `wayvnc.Dockerfile`: wayvnc on a headless sway desktop, set up the way Raspberry Pi OS sets it up (a certificate, and a username and
  password checked by the system).

The test hosts use `raspberry` as the password (and `pi` as the username where one is asked for). It checks a wrong password,
the first-use certificate prompt, and that a trusted certificate does not ask twice. Screenshots land in `out/`.
