# corpus

The pcap corpus. `manifest.yaml` lists every capture by sha256, with its
source, licence, size, packet count, average packet size and ground-truth file
(plan §B6). `mbench validate corpus/manifest.yaml` checks it against the
committed schema `src/mbench/schemas/corpus-manifest.schema.json`.

Packet captures are never committed. `.gitignore` excludes `*.pcap`, `*.pcapng`,
their compressed forms (`*.pcap.*`, `*.pcapng.*`), `*.cap`, `*.erf`, and
`corpus/data/`, the local directory where pcaps are downloaded or generated.
`tools/ci/check_no_captures.py` enforces it in CI, by name and by magic bytes.

```sh
uv run mbench corpus gen c-small        # 64 B frames, deterministic (--seed)
uv run mbench corpus gen c-large        # 1500 B frames
uv run mbench corpus check              # every file present vs its sha256
uv run mbench corpus add data/x.pcap --source ... --licence ...
```

`gen` needs no packet tool: the synthetic sets are written in pure Python and
are byte-for-byte reproducible from the set, the seed and the packet and flow
counts, which the entry records under `generator`.

`check` exits non-zero when a file's sha256 differs from its entry. A missing
file is reported but not an error: captures are not committed, so any of them
can be absent and regenerated or fetched again.

An entry marked `local_only` (the anonymised dgx-spark capture) is never
committed or published: results and reports show only its label and sha256.
