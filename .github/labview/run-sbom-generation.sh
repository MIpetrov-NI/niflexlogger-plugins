#!/usr/bin/env bash
set -euo pipefail

workspace="${1:-/workspace}"
out_dir="${2:-/workspace/ci-out/sbom/results}"
labview_version="${LABVIEW_VERSION:-2026}"

mkdir -p "$out_dir"

find_vipm() {
  if command -v vipm >/dev/null 2>&1; then
    command -v vipm
    return
  fi
  if command -v vipm-cli >/dev/null 2>&1; then
    command -v vipm-cli
    return
  fi
  find /usr/local /usr /opt -type f \( -name vipm -o -name vipm-cli \) -perm -111 2>/dev/null | head -n 1
}

find_labview() {
  local candidate="/usr/local/natinst/LabVIEW-${labview_version}-64/labview"
  if [ -x "$candidate" ]; then
    printf '%s\n' "$candidate"
    return
  fi
  find /usr/local/natinst /usr /opt -type f -name labview -perm -111 2>/dev/null | head -n 1
}

find_project() {
  find "$workspace" \
    \( -path "$workspace/.github" -o -path "$workspace/ci-out" -o -path "$workspace/build" \) -prune \
    -o -type f -iname '*.lvproj' -print | sort | head -n 1
}

vipm_bin="$(find_vipm || true)"
labview_bin="$(find_labview || true)"
project="$(find_project || true)"
out_path="$out_dir/sbom.json"

if [ -z "$vipm_bin" ]; then
  echo "VIPM CLI was not found in the Linux worker." >&2
  exit 1
fi
if [ -z "$labview_bin" ]; then
  echo "LabVIEW ${labview_version} was not found in the Linux worker." >&2
  exit 1
fi
if [ -z "$project" ]; then
  echo "No project .lvproj file was found under $workspace." >&2
  exit 1
fi

export DISPLAY="${DISPLAY:-:99}"
export VIPM_NONINTERACTIVE="${VIPM_NONINTERACTIVE:-1}"
export VIPM_ASSUME_YES="${VIPM_ASSUME_YES:-1}"
export NO_COLOR="${NO_COLOR:-1}"
export CI="${CI:-true}"
unset LV_RTE_HEADLESS || true

xvfb_pid=""
labview_pid=""
cleanup() {
  if [ -n "$labview_pid" ]; then kill "$labview_pid" 2>/dev/null || true; fi
  if [ -n "$xvfb_pid" ]; then kill "$xvfb_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT

if command -v Xvfb >/dev/null 2>&1 && ! pgrep -x Xvfb >/dev/null 2>&1; then
  Xvfb "$DISPLAY" -screen 0 1280x720x24 -ac +extension GLX +render -noreset >/tmp/sbom-xvfb.log 2>&1 &
  xvfb_pid="$!"
fi
mkdir -p /tmp/natinst
echo "1" >/tmp/natinst/LVContainer.txt

labview_args=(--headless)
if [ -f /app/labview.conf ]; then
  labview_args=(-pref /app/labview.conf --headless)
fi
"$labview_bin" "${labview_args[@]}" >/tmp/sbom-labview.log 2>&1 &
labview_pid="$!"

echo "=== JKI VIPM SBOM Generation (Linux) ==="
echo "  Workspace : $workspace"
echo "  Project   : $project"
echo "  Results   : $out_path"
echo "  VIPM CLI  : $vipm_bin"
echo "  LabVIEW   : $labview_bin"
"$vipm_bin" --version || true

# Give LabVIEW and its VI Server a short head start. VIPM performs its own
# startup wait and returns a non-zero exit if the desktop engine cannot connect.
sleep 5

"$vipm_bin" \
  --labview-version "$labview_version" \
  --labview-bitness 64 \
  sbom "$project" \
  --format cyclonedx \
  --schema-version 1.5 \
  --allow-missing-files \
  --output "$out_path"

if [ ! -s "$out_path" ]; then
  echo "VIPM reported success but did not create $out_path." >&2
  exit 1
fi
if ! grep -Eq '"bomFormat"[[:space:]]*:[[:space:]]*"CycloneDX"' "$out_path"; then
  echo "VIPM output is not a CycloneDX document: $out_path" >&2
  exit 1
fi

python3 "$workspace/.github/labview/enrich-sbom-linux.py" \
  --sbom "$out_path" \
  --project "$project" \
  --labview-bin "$labview_bin"

echo "Linux CycloneDX SBOM generated successfully: $out_path"
