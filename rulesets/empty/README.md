# rulesets/empty

Deliberately empty: the rules path of the `r0` and `r0b` definitions
(#10). `r0` runs mmt-probe with `security.enable = false`; `r0b` runs it
with the security engine on and zero rules to match. Both definitions set
`allow_empty: true`, so the adapter's "no .so rule staged" guard still
catches a silently missing extraction for every other ruleset.
