#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -lt 4 ]]; then
  echo "usage: $0 <output-dir> <threshold-percent> <target-file>... -- <command> [args...]" >&2
  exit 2
fi

output_dir="${1:?output dir required}"
threshold="${2:?threshold required}"
shift 2

targets=()
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--" ]]; then
    shift
    break
  fi
  targets+=("$1")
  shift
done

if [[ "${#targets[@]}" -eq 0 || "$#" -eq 0 ]]; then
  echo "usage: $0 <output-dir> <threshold-percent> <target-file>... -- <command> [args...]" >&2
  exit 2
fi

mkdir -p "${output_dir}"
trace_file="${output_dir}/trace.log"
report_json="${output_dir}/coverage.json"
report_txt="${output_dir}/coverage.txt"

canon_targets=()
for target in "${targets[@]}"; do
  canon_targets+=("$(realpath "${target}")")
done

exec 9>"${trace_file}"
export BASH_XTRACEFD=9
export PS4='+${BASH_SOURCE[0]-$0}:${LINENO}:'
export SHELLOPTS

set -x
"$@"
set +x
exec 9>&-

python3 - "${report_json}" "${report_txt}" "${threshold}" "${trace_file}" "${canon_targets[@]}" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def is_coverable(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    if stripped in {"then", "do", "fi", "done", "esac", "else", "{", "}", ";;"}:
        return False
    if stripped.startswith("else ") or stripped.startswith("elif ") or stripped == "in":
        return False
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\(\)\s*\{(\s*[^}]*)?\}\s*$", stripped):
        return False
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\(\)\s*\{$", stripped):
        return False
    if re.match(r"^[A-Za-z0-9_.*|:-]+\)\s*$", stripped):
        return False
    return True


report_json = Path(sys.argv[1])
report_txt = Path(sys.argv[2])
threshold = float(sys.argv[3])
trace_file = Path(sys.argv[4])
cwd = Path.cwd().resolve()
targets = [Path(p).resolve() for p in sys.argv[5:]]
target_set = {str(p) for p in targets}
target_suffix_map: dict[str, str] = {}
for target in targets:
    key = str(target)
    try:
        rel = target.relative_to(cwd)
        target_suffix_map[str(rel)] = key
    except ValueError:
        pass

coverable: dict[str, set[int]] = {}
for target in targets:
    lines = set()
    skip_heredoc_until = ""
    skip_continuation = False
    for lineno, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if skip_heredoc_until:
            if stripped == skip_heredoc_until:
                skip_heredoc_until = ""
            continue
        if skip_continuation:
            skip_continuation = stripped.endswith("\\")
            continue
        heredoc = re.search(r"<<[-]?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", stripped)
        if heredoc:
            skip_heredoc_until = heredoc.group(1)
        if is_coverable(line):
            lines.add(lineno)
        if stripped.endswith("\\"):
            skip_continuation = True
    coverable[str(target)] = lines

executed: dict[str, set[int]] = {str(t): set() for t in targets}
line_re = re.compile(r"^\++([^:]+):([0-9]+):")
for raw_line in trace_file.read_text(encoding="utf-8", errors="replace").splitlines():
    match = line_re.match(raw_line)
    if not match:
        continue
    src = match.group(1)
    try:
        lineno = int(match.group(2))
    except ValueError:
        continue
    src_path = Path(src)
    if not src_path.is_absolute():
      src_path = (Path.cwd() / src_path).resolve()
    else:
      src_path = src_path.resolve()
    src_str = str(src_path)
    target_key = src_str if src_str in target_set else ""
    if not target_key:
        for suffix, key in target_suffix_map.items():
            if src_str.endswith(f"/{suffix}") or src_str == suffix:
                target_key = key
                break
    if not target_key:
        continue
    if lineno in coverable[target_key]:
        executed[target_key].add(lineno)

files = []
total_coverable = 0
total_executed = 0
for target in targets:
    key = str(target)
    file_coverable = len(coverable[key])
    file_executed = len(executed[key])
    pct = 100.0 if file_coverable == 0 else (file_executed / file_coverable) * 100.0
    files.append(
        {
            "path": key,
            "coverable_lines": file_coverable,
            "executed_lines": file_executed,
            "coverage_percent": round(pct, 2),
            "uncovered_lines": sorted(coverable[key] - executed[key]),
        }
    )
    total_coverable += file_coverable
    total_executed += file_executed

overall = 100.0 if total_coverable == 0 else (total_executed / total_coverable) * 100.0
status = "pass" if overall >= threshold else "fail"
payload = {
    "status": status,
    "threshold_percent": threshold,
    "coverage_percent": round(overall, 2),
    "executed_lines": total_executed,
    "coverable_lines": total_coverable,
    "files": files,
}
report_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

lines = [
    f"shell coverage: {payload['coverage_percent']:.2f}% (threshold {threshold:.2f}%)",
    f"executed {total_executed} / coverable {total_coverable}",
]
for item in files:
    lines.append(
        f"{item['path']}: {item['coverage_percent']:.2f}% "
        f"({item['executed_lines']}/{item['coverable_lines']})"
    )
report_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(report_txt.read_text(encoding="utf-8"), end="")
sys.exit(0 if status == "pass" else 1)
PY
