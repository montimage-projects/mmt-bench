#!/bin/sh
# mmt-bench probe image entrypoint: dispatch to one of the installed tools.
#   probe <args>               /opt/mmt/probe/bin/probe <args>
#   rule_info <args>           /opt/mmt/security/bin/rule_info <args>
#   mmt_sec_standalone <args>  /opt/mmt/security/bin/mmt_security <args>
#   versions                   print /opt/mmt/VERSIONS then `probe -v`
# Anything else is executed verbatim.
set -eu
cmd="${1:-}"
case "$cmd" in
  probe)
    shift; exec /opt/mmt/probe/bin/probe "$@" ;;
  rule_info)
    shift; exec /opt/mmt/security/bin/rule_info "$@" ;;
  mmt_sec_standalone)
    shift; exec /opt/mmt/security/bin/mmt_security "$@" ;;
  versions)
    cat /opt/mmt/VERSIONS
    /opt/mmt/probe/bin/probe -v
    exit 0 ;;
  "")
    echo "usage: probe|rule_info|mmt_sec_standalone|versions|<command>" >&2
    exit 2 ;;
  *)
    exec "$@" ;;
esac
