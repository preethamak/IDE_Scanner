#!/usr/bin/env bash
set -euo pipefail

# Run only static scanning of already-acquired benchmark VSIX files. This
# script never downloads, installs, activates, or executes an extension.
# Acquisition is a separate, hash-pinned process; see the benchmark protocol.

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <artifact-directory> <result-directory>" >&2
  exit 64
fi

ARTIFACTS="$(realpath "$1")"
RESULTS="$(realpath -m "$2")"
IMAGE="${IDE_SCANNER_STATIC_BENCHMARK_IMAGE:-ide-scanner-static-benchmark:local}"

if [[ ! -d "$ARTIFACTS" ]]; then
  echo "Artifact directory does not exist: $ARTIFACTS" >&2
  exit 66
fi

if ! find "$ARTIFACTS" -type f -name '*.vsix' -print -quit | grep -q .; then
  echo "No .vsix artifacts found in: $ARTIFACTS" >&2
  exit 66
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Missing scanner image: $IMAGE" >&2
  echo "Build it first with scripts/build-static-benchmark-image.sh" >&2
  exit 69
fi

mkdir -p "$RESULTS"
# The unprivileged container user needs to write a report. Artifacts remain
# mounted read-only. Results are untrusted scanner output, not source input.
chmod ugo+rwx "$RESULTS"

exec docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --memory 3g \
  --cpus 1.0 \
  --user 65534:65534 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=512m \
  --mount "type=bind,src=$ARTIFACTS,dst=/input,readonly" \
  --mount "type=bind,src=$RESULTS,dst=/output" \
  --workdir /tmp \
  --entrypoint /bin/sh \
  "$IMAGE" \
  -ec '
    find /input -type f -name "*.vsix" -print > /tmp/vsix-files
    set -- python -m ide_scanner scan --format json --output /output/static-scan.json
    while IFS= read -r artifact; do
      set -- "$@" --path "$artifact"
    done < /tmp/vsix-files
    exec "$@"
  '
