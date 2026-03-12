#!/usr/bin/env bash
set -euo pipefail
# Helper: tests lane_on_err by running a failing script and checking the report.
# Usage: bash test-lane-on-err.sh /path/to/lane-runtime.sh

LANE_RUNTIME="${1:?lane-runtime.sh path required}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

# Write a script that sources lane-runtime, inits, and fails
cat > "${tmpdir}/fail.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$1"
lane_init "test-lane" "$2"
trap 'lane_on_err "${LINENO}" "${BASH_COMMAND}"' ERR
CI_LANE_STAGE="my_step"
false
SCRIPT

bash "${tmpdir}/fail.sh" "${LANE_RUNTIME}" "${tmpdir}" >/dev/null 2>&1 || true

python3 -c "
import json, sys
r = json.load(open('${tmpdir}/outputs/ci/test-lane/report.json'))
assert r['status'] == 'fail', f'expected fail, got {r[\"status\"]}'
assert r['stage'] == 'my_step', f'expected my_step, got {r[\"stage\"]}'
print(r['status'])
"
