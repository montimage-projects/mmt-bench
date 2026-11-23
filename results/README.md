# results

Campaign results, append-only: `results/<date>-<campaign>/{runs/*.json, sut.json,
REPORT.md}`. A result directory is never overwritten. Written by `mbench run` (#8).

Every run embeds its full SUT record (`mbench sut`, #4); a run without a complete
record is invalid and excluded from every table (#8).

A tool-comparison report (mmt vs Suricata vs Snort) is not committed: it stays
under the git-ignored `local/` until it passes the licence and fairness review
(AGENTS.md, design decision 1).
