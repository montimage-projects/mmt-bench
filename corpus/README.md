# corpus

The pcap corpus. `manifest.yaml` (#7) lists every pcap by sha256, with its source,
licence, size, packet count, average packet size and ground-truth file.

Packet captures are never committed. `.gitignore` excludes `*.pcap`, `*.pcapng`,
their compressed forms (`*.pcap.*`, `*.pcapng.*`), `*.cap`, `*.erf`, and
`corpus/data/`, the local directory where pcaps are downloaded or generated.
The anonymised dgx-spark capture stays local only and is never published.
