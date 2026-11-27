# tools/docker

Container images for the tools under test and the traffic replayer (mmt-probe,
Suricata, Snort 3, tcpreplay/trafgen), each pinned by digest. Packet tools come in
containers; nothing is installed on the host.

- [mmt-probe/](mmt-probe/) — the mmt-probe image (#6): mmt-dpi 1.10.3,
  mmt-security (fork `main` @ `19be37cb`) and mmt-probe (fork
  `intact-new-features` @ `7f4710d9`), all pinned, STIX + security modules.
- [tcpreplay/](tcpreplay/) — tcprewrite (the C-benign anonymiser) and
  tcpdump (its no-sudo capture, #50), apt-version-pinned on the same
  Ubuntu base.
- Suricata (#14) and the replayer (#13): filled in by their issues.
