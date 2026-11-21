# tools/docker

Container images for the tools under test and the traffic replayer (mmt-probe,
Suricata, Snort 3, tcpreplay/trafgen), each pinned by digest. Packet tools come in
containers; nothing is installed on the host.

- [mmt-probe/](mmt-probe/) — the mmt-probe image (#6): mmt-dpi 1.10.3,
  mmt-security (fork `main` @ `defefb7a`) and mmt-probe, all pinned, STIX +
  security modules.
- Suricata (#14) and the replayer (#13): filled in by their issues.
