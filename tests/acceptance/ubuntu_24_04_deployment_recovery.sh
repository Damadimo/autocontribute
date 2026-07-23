#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

readonly service_account="autocontribute"
readonly service_home="/var/lib/autocontribute"
readonly state_root="${service_home}/state"
readonly backup_root="/var/backups/autocontribute"
readonly application_root="/opt/autocontribute"
readonly releases_root="${application_root}/releases"
readonly current_release="${application_root}/current"
readonly config_root="/etc/autocontribute"
readonly production_config="${config_root}/autocontribute.yml"
readonly clean_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

smoke_root=""
release=""
release_id=""
acceptance_marker=""
service_uid=""
service_gid=""
state_image=""
backup_image=""
state_loop=""
backup_loop=""
state_mounted=0
backup_mounted=0
account_created=0
application_root_created=0
config_root_created=0
runtime_root_created=0
backup_root_created=0
assets_install_started=0
current_created=0
systemd_reloaded=0
temporary_base="/tmp"
libexec_created=0
source_mode="git"
source_root=""
requested_source_root=""

fail() {
  printf 'Ubuntu deployment/recovery acceptance failed: %s\n' "$1" >&2
  exit 1
}

require_absent() {
  local path="$1"
  if sudo test -e "$path" || sudo test -L "$path"; then
    fail "refusing to use a host with an existing production path: $path"
  fi
}

remove_marked_tree() {
  local root="$1"
  local marker_path="${root}/.autocontribute-acceptance"
  if ! sudo test -f "$marker_path"; then
    printf 'Refusing to clean an unmarked acceptance path: %s\n' "$root" >&2
    return 1
  fi
  if [[ "$(sudo /bin/cat -- "$marker_path")" != "$acceptance_marker" ]]; then
    printf 'Refusing to clean an acceptance path with the wrong marker: %s\n' "$root" >&2
    return 1
  fi
  sudo /bin/rm -rf -- "$root"
}

cleanup() {
  local exit_status=$?
  local actual_backup_source=""
  local actual_state_source=""
  local backup_mount_status=0
  local cleanup_failed=0
  local backup_backing=""
  local path
  local state_mount_status=0
  local state_backing=""
  trap - EXIT
  set +e

  if [[ "$systemd_reloaded" -eq 1 ]]; then
    for path in \
      autocontribute-worker.timer \
      autocontribute-health.timer \
      autocontribute-backup.timer \
      autocontribute-backup.service \
      autocontribute-failure@autocontribute-backup.service.service; do
      sudo systemctl stop "$path" >/dev/null 2>&1 || true
    done
  fi

  sudo mountpoint --quiet -- "$backup_root"
  backup_mount_status=$?
  if [[ "$backup_mount_status" -eq 0 ]]; then
    actual_backup_source="$(
      sudo findmnt --noheadings --raw --output SOURCE --mountpoint "$backup_root"
    )"
    if [[ -z "$backup_loop" || "$actual_backup_source" != "$backup_loop" ]]; then
      printf 'Refusing to unmount unexpected backup storage\n' >&2
      backup_mounted=1
      cleanup_failed=1
    else
      if [[ "$backup_mounted" -ne 1 ]]; then
        printf 'Acceptance backup mount existed without recorded ownership\n' >&2
        cleanup_failed=1
      fi
      if sudo umount -- "$backup_root"; then
        backup_mounted=0
      else
        printf 'Could not unmount acceptance backup storage\n' >&2
        backup_mounted=1
        cleanup_failed=1
      fi
    fi
  elif [[ "$backup_mount_status" -eq 32 ]]; then
    if [[ "$backup_mounted" -eq 1 ]]; then
      printf 'Acceptance backup storage is no longer the expected mount\n' >&2
      backup_mounted=0
      cleanup_failed=1
    fi
  else
    printf 'Could not inspect the acceptance backup mountpoint\n' >&2
    backup_mounted=1
    cleanup_failed=1
  fi
  sudo mountpoint --quiet -- "$state_root"
  state_mount_status=$?
  if [[ "$state_mount_status" -eq 0 ]]; then
    actual_state_source="$(
      sudo findmnt --noheadings --raw --output SOURCE --mountpoint "$state_root"
    )"
    if [[ -z "$state_loop" || "$actual_state_source" != "$state_loop" ]]; then
      printf 'Refusing to unmount unexpected state storage\n' >&2
      state_mounted=1
      cleanup_failed=1
    else
      if [[ "$state_mounted" -ne 1 ]]; then
        printf 'Acceptance state mount existed without recorded ownership\n' >&2
        cleanup_failed=1
      fi
      if sudo umount -- "$state_root"; then
        state_mounted=0
      else
        printf 'Could not unmount acceptance state storage\n' >&2
        state_mounted=1
        cleanup_failed=1
      fi
    fi
  elif [[ "$state_mount_status" -eq 32 ]]; then
    if [[ "$state_mounted" -eq 1 ]]; then
      printf 'Acceptance state storage is no longer the expected mount\n' >&2
      state_mounted=0
      cleanup_failed=1
    fi
  else
    printf 'Could not inspect the acceptance state mountpoint\n' >&2
    state_mounted=1
    cleanup_failed=1
  fi

  if [[ -n "$backup_loop" && "$backup_mounted" -eq 0 ]]; then
    backup_backing="$(
      sudo losetup --noheadings --output BACK-FILE "$backup_loop" 2>/dev/null | \
        awk '{$1=$1; print}'
    )"
    if [[ "$backup_backing" != "$backup_image" ]]; then
      printf 'Refusing to detach an unexpected backup loop device\n' >&2
      cleanup_failed=1
    elif sudo losetup --detach "$backup_loop"; then
      backup_loop=""
    else
      printf 'Could not detach acceptance backup loop device\n' >&2
      cleanup_failed=1
    fi
  fi
  if [[ -n "$state_loop" && "$state_mounted" -eq 0 ]]; then
    state_backing="$(
      sudo losetup --noheadings --output BACK-FILE "$state_loop" 2>/dev/null | \
        awk '{$1=$1; print}'
    )"
    if [[ "$state_backing" != "$state_image" ]]; then
      printf 'Refusing to detach an unexpected state loop device\n' >&2
      cleanup_failed=1
    elif sudo losetup --detach "$state_loop"; then
      state_loop=""
    else
      printf 'Could not detach acceptance state loop device\n' >&2
      cleanup_failed=1
    fi
  fi

  if [[ "$assets_install_started" -eq 1 ]]; then
    sudo /bin/rm -f -- \
      /etc/systemd/system/autocontribute-backup.service \
      /etc/systemd/system/autocontribute-backup.timer \
      /etc/systemd/system/autocontribute-doctor.service \
      /etc/systemd/system/autocontribute-failure@.service \
      /etc/systemd/system/autocontribute-health.service \
      /etc/systemd/system/autocontribute-health.timer \
      /etc/systemd/system/autocontribute-rootless-docker.service \
      /etc/systemd/system/autocontribute-worker.service \
      /etc/systemd/system/autocontribute-worker.timer \
      /etc/systemd/user/autocontribute-rootless-docker-daemon.service \
      /etc/tmpfiles.d/autocontribute.conf \
      /usr/local/libexec/autocontribute-backup \
      /usr/local/libexec/autocontribute-docker-data-check \
      /usr/local/libexec/autocontribute-healthcheck \
      /usr/local/libexec/autocontribute-record-failure \
      /usr/local/libexec/autocontribute-rootless-docker \
      /usr/local/libexec/autocontribute-rootless-docker-check \
      /usr/local/libexec/autocontribute-rootless-dockerd \
      /usr/local/libexec/autocontribute-storage-capacity-check \
      /usr/local/libexec/autocontribute-worker \
      /usr/local/libexec/autocontribute-workspace-quota-check || cleanup_failed=1
    if [[ -n "$service_uid" ]]; then
      sudo /bin/rm -f -- \
        "/etc/systemd/system/user@${service_uid}.service.d/50-autocontribute.conf" || \
        cleanup_failed=1
      sudo rmdir -- "/etc/systemd/system/user@${service_uid}.service.d" \
        >/dev/null 2>&1 || true
    fi
    if [[ "$libexec_created" -eq 1 ]]; then
      sudo rmdir -- /usr/local/libexec >/dev/null 2>&1 || cleanup_failed=1
    fi
  fi

  if [[ "$assets_install_started" -eq 1 ]]; then
    sudo systemctl daemon-reload >/dev/null 2>&1 || cleanup_failed=1
    sudo systemctl reset-failed >/dev/null 2>&1 || true
  fi

  if [[ "$config_root_created" -eq 1 ]]; then
    remove_marked_tree "$config_root" || cleanup_failed=1
  fi
  if [[ "$backup_root_created" -eq 1 ]]; then
    sudo mountpoint --quiet -- "$backup_root"
    backup_mount_status=$?
    if [[ "$backup_mounted" -ne 0 || "$backup_mount_status" -eq 0 ]]; then
      printf 'Refusing to remove a mounted acceptance backup root\n' >&2
      cleanup_failed=1
    elif [[ "$backup_mount_status" -ne 32 ]]; then
      printf 'Refusing to remove an unverified acceptance backup root\n' >&2
      cleanup_failed=1
    else
      remove_marked_tree "$backup_root" || cleanup_failed=1
    fi
  fi
  if [[ "$runtime_root_created" -eq 1 ]]; then
    sudo mountpoint --quiet -- "$state_root"
    state_mount_status=$?
    if [[ "$state_mounted" -ne 0 || "$state_mount_status" -eq 0 ]]; then
      printf 'Refusing to remove a service home containing mounted acceptance state\n' >&2
      cleanup_failed=1
    elif [[ "$state_mount_status" -ne 32 ]]; then
      printf 'Refusing to remove a service home with unverified mount state\n' >&2
      cleanup_failed=1
    else
      remove_marked_tree "$service_home" || cleanup_failed=1
    fi
  fi

  if [[ "$current_created" -eq 1 ]]; then
    if sudo test -L "$current_release" && \
      [[ "$(sudo readlink -- "$current_release")" == "releases/${release_id}" ]]; then
      sudo unlink -- "$current_release" || cleanup_failed=1
    else
      printf 'Refusing to remove an unexpected current-release path\n' >&2
      cleanup_failed=1
    fi
  fi
  if [[ -n "$release" ]] && sudo test -e "$release"; then
    remove_marked_tree "$release" || cleanup_failed=1
  fi
  if [[ "$application_root_created" -eq 1 ]]; then
    sudo rmdir -- "$releases_root" >/dev/null 2>&1 || true
    if sudo test -f "${application_root}/.autocontribute-acceptance" && \
      [[ "$(sudo /bin/cat -- "${application_root}/.autocontribute-acceptance")" == \
        "$acceptance_marker" ]]; then
      sudo /bin/rm -f -- "${application_root}/.autocontribute-acceptance" || cleanup_failed=1
      sudo rmdir -- "$application_root" >/dev/null 2>&1 || cleanup_failed=1
    else
      printf 'Refusing to clean an unmarked application root\n' >&2
      cleanup_failed=1
    fi
  fi

  if [[ "$account_created" -eq 1 ]]; then
    sudo userdel "$service_account" >/dev/null 2>&1 || cleanup_failed=1
    if getent group "$service_account" >/dev/null; then
      sudo groupdel "$service_account" >/dev/null 2>&1 || cleanup_failed=1
    fi
  fi

  if [[ -n "$smoke_root" && -d "$smoke_root" ]]; then
    case "$smoke_root" in
      "${temporary_base%/}"/autocontribute-deployment-recovery.*)
        if [[ "$backup_mounted" -ne 0 || "$state_mounted" -ne 0 ||
              -n "$backup_loop" || -n "$state_loop" ]]; then
          printf 'Refusing to remove storage still used by acceptance resources: %s\n' \
            "$smoke_root" >&2
          cleanup_failed=1
        else
          /bin/rm -rf -- "$smoke_root" || cleanup_failed=1
        fi
        ;;
      *)
        printf 'Refusing to clean an unexpected smoke root: %s\n' "$smoke_root" >&2
        cleanup_failed=1
        ;;
    esac
  fi

  if [[ "$exit_status" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    exit_status=1
  fi
  exit "$exit_status"
}
trap cleanup EXIT

case "$#" in
  0) ;;
  2)
    [[ "$1" == "--source-root" && -n "$2" ]] || \
      fail "usage: $0 [--source-root ABSOLUTE_EXTRACTED_SDIST_ROOT]"
    source_mode="sdist"
    requested_source_root="$2"
    ;;
  *) fail "usage: $0 [--source-root ABSOLUTE_EXTRACTED_SDIST_ROOT]" ;;
esac
if [[ "$UID" -eq 0 ]]; then
  fail "run as a non-root administrator with passwordless sudo"
fi

for required_command in \
  awk find findmnt getent git install losetup mkfs.ext4 mount mountpoint \
  readlink sha256sum stat sudo systemctl systemd-analyze systemd-tmpfiles \
  tar truncate umount uv; do
  command -v "$required_command" >/dev/null || fail "missing command: $required_command"
done
unset required_command

[[ -r /etc/os-release ]] || fail "/etc/os-release is unavailable"
# The file is distribution-owned on the disposable acceptance host.
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || \
  fail "the controlled baseline is Ubuntu 24.04"
[[ "$(uname --machine)" == "x86_64" ]] || fail "the supported production architecture is amd64"
[[ "$(/bin/cat /proc/1/comm)" == "systemd" ]] || fail "systemd must be PID 1"
systemd_major="$(systemd-analyze --version | awk 'NR == 1 { print $2 }')"
[[ "$systemd_major" == "255" ]] || fail "the reviewed systemd major is 255"
unset systemd_major
sudo --non-interactive true || fail "passwordless sudo is required"

if [[ "$source_mode" == "git" ]]; then
  source_root="$(git rev-parse --show-toplevel)"
  [[ -e "$source_root/.git" ]] || fail "run from the Autocontribute Git checkout"
  [[ "$(git -C "$source_root" rev-parse --is-inside-work-tree)" == "true" ]] || \
    fail "the source root is not a Git worktree"
  [[ -z "$(git -C "$source_root" status --porcelain --untracked-files=normal)" ]] || \
    fail "commit or remove every worktree change before testing the immutable release"
else
  [[ "$requested_source_root" == /* && "$requested_source_root" != / ]] || \
    fail "the extracted sdist source root must be an absolute non-root path"
  [[ ! -L "$requested_source_root" ]] || fail "the extracted sdist source root is a symlink"
  source_root="$(readlink --canonicalize-existing "$requested_source_root")"
  [[ "$source_root" == "$requested_source_root" && -d "$source_root" ]] || \
    fail "the extracted sdist source root must be one exact real directory"
  [[ -f "$source_root/PKG-INFO" && ! -L "$source_root/PKG-INFO" ]] || \
    fail "the explicit source root is not an extracted Python source distribution"
  [[ ! -e "$source_root/.git" && ! -e "$source_root/.venv" ]] || \
    fail "the extracted sdist source root contains development state"
  unsafe_source_entry="$(
    find "$source_root" -mindepth 1 ! \( -type d -o -type f \) -print -quit
  )"
  [[ -z "$unsafe_source_entry" ]] || \
    fail "the extracted sdist contains an unsafe entry: $unsafe_source_entry"
  unset unsafe_source_entry
fi

for required_source_file in \
  pyproject.toml \
  uv.lock \
  src/autocontribute/_build_identity.json \
  src/autocontribute/_systemd_assets.json; do
  [[ -f "$source_root/$required_source_file" && ! -L "$source_root/$required_source_file" ]] || \
    fail "release source is missing a required regular file: $required_source_file"
done
unset required_source_file
if [[ -e "$source_root/.autocontribute-acceptance" || \
  -L "$source_root/.autocontribute-acceptance" ]]; then
  fail "release source uses the reserved acceptance cleanup marker"
fi

/usr/bin/python3 - "$source_root" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest = json.loads(
    (root / "src" / "autocontribute" / "_build_identity.json").read_text(encoding="utf-8")
)
expected = {
    "project": "autocontribute",
    "pyproject_sha256": hashlib.sha256((root / "pyproject.toml").read_bytes()).hexdigest(),
    "schema_version": 1,
    "uv_lock_sha256": hashlib.sha256((root / "uv.lock").read_bytes()).hexdigest(),
}
if manifest != expected:
    raise SystemExit("release build identity does not match its project and lock material")
PY

if getent passwd "$service_account" >/dev/null || getent group "$service_account" >/dev/null; then
  fail "refusing to use a host that already has the Autocontribute service identity"
fi
require_absent "$application_root"
require_absent "$config_root"
require_absent "$service_home"
require_absent "$backup_root"
require_absent /etc/tmpfiles.d/autocontribute.conf
require_absent /etc/systemd/user/autocontribute-rootless-docker-daemon.service
require_absent /etc/systemd/system/user@.service.d/50-autocontribute.conf
require_absent /etc/systemd/system/user@.service.d/delegate.conf

for managed_directory in /etc/systemd/system /usr/local/libexec; do
  existing_path="$(
    sudo find "$managed_directory" -mindepth 1 -maxdepth 1 \
      -name 'autocontribute*' -print -quit 2>/dev/null || true
  )"
  [[ -z "$existing_path" ]] || fail "existing managed path: $existing_path"
done
unset existing_path managed_directory

temporary_base="${RUNNER_TEMP:-/tmp}"
[[ -d "$temporary_base" && ! -L "$temporary_base" ]] || \
  fail "the disposable temporary base is unavailable"
temporary_base="$(readlink --canonicalize-existing "$temporary_base")"
smoke_root="$(mktemp --directory "${temporary_base}/autocontribute-deployment-recovery.XXXXXX")"
smoke_root="$(readlink --canonicalize-existing "$smoke_root")"
acceptance_marker="$(/bin/cat /proc/sys/kernel/random/uuid)"
printf '%s\n' "$acceptance_marker" >"${smoke_root}/marker"

sudo useradd \
  --system \
  --user-group \
  --home-dir "$service_home" \
  --no-create-home \
  --shell /usr/sbin/nologin \
  "$service_account"
account_created=1
service_uid="$(id --user "$service_account")"
service_gid="$(id --group "$service_account")"
[[ "$service_uid" =~ ^[1-9][0-9]*$ && "$service_gid" =~ ^[1-9][0-9]*$ ]] || \
  fail "the service identity is invalid"
require_absent "/etc/systemd/system/user@${service_uid}.service.d"

if [[ "$source_mode" == "git" ]]; then
  release_identity="$(git -C "$source_root" rev-parse --short=12 HEAD)"
else
  release_digest="$(sha256sum "$source_root/PKG-INFO" | awk '{print $1}')"
  [[ "$release_digest" =~ ^[0-9a-f]{64}$ ]] || fail "the sdist identity digest is invalid"
  release_identity="${release_digest:0:12}"
  unset release_digest
fi
release_id="acceptance-${release_identity}-$$"
unset release_identity
release="${releases_root}/${release_id}"
sudo install -d -o root -g root -m 0755 "$application_root" "$releases_root"
sudo install -o root -g root -m 0600 \
  "${smoke_root}/marker" "${application_root}/.autocontribute-acceptance"
application_root_created=1
sudo install -d -o "$UID" -g "$(id --group)" -m 0755 "$release"
install -m 0600 "${smoke_root}/marker" "${release}/.autocontribute-acceptance"
if [[ "$source_mode" == "git" ]]; then
  git -C "$source_root" archive --format=tar HEAD | tar --extract --file=- --directory "$release"
else
  tar --create --file=- --directory "$source_root" . | \
    tar --extract --file=- --directory "$release"
fi

uv sync \
  --project "$release" \
  --frozen \
  --no-dev \
  --python /usr/bin/python3
sudo chown -R root:root "$release"
sudo chmod -R go-w "$release"

sudo "${release}/.venv/bin/autocontribute" \
  deployment verify-systemd-assets --source-root "$release"

mapfile -d '' -t system_units < <(
  find "${release}/deploy/systemd" -maxdepth 1 -type f \
    \( -name '*.service' -o -name '*.timer' \) -print0 | sort -z
)
mapfile -d '' -t helpers < <(
  find "${release}/deploy/systemd/libexec" -maxdepth 1 -type f -print0 | sort -z
)
[[ "${#system_units[@]}" -eq 9 ]] || fail "the release must contain nine system units"
[[ "${#helpers[@]}" -eq 10 ]] || fail "the release must contain ten helpers"

assets_install_started=1
for shared_directory in /etc/systemd/system /etc/systemd/user /etc/tmpfiles.d; do
  if ! sudo test -d "$shared_directory" || sudo test -L "$shared_directory"; then
    fail "required system directory is unavailable or unsafe: $shared_directory"
  fi
done
unset shared_directory
sudo test ! -L /usr/local/libexec || fail "/usr/local/libexec must not be a symbolic link"
if ! sudo test -d /usr/local/libexec; then
  sudo install -d -o root -g root -m 0755 /usr/local/libexec
  libexec_created=1
fi
sudo install -d -o root -g root -m 0755 \
  "/etc/systemd/system/user@${service_uid}.service.d"
sudo install -o root -g root -m 0644 "${system_units[@]}" /etc/systemd/system/
sudo install -o root -g root -m 0755 "${helpers[@]}" /usr/local/libexec/
sudo install -o root -g root -m 0644 \
  "${release}/deploy/systemd/user/autocontribute-rootless-docker-daemon.service" \
  /etc/systemd/user/autocontribute-rootless-docker-daemon.service
sudo install -o root -g root -m 0644 \
  "${release}/deploy/systemd/autocontribute-user-manager.conf" \
  "/etc/systemd/system/user@${service_uid}.service.d/50-autocontribute.conf"
sudo install -o root -g root -m 0644 \
  "${release}/deploy/systemd/autocontribute.tmpfiles.conf" \
  /etc/tmpfiles.d/autocontribute.conf

sudo ln --symbolic "releases/${release_id}" "$current_release"
current_created=1
[[ "$(sudo readlink --canonicalize-existing "$current_release")" == "$release" ]] || \
  fail "the selected release does not resolve to the immutable release directory"

verify_installed_assets() {
  sudo "${current_release}/.venv/bin/autocontribute" deployment verify-systemd-assets
}

verify_installed_assets

# Prove installed attestation fails closed on drift, then restore the reviewed mode.
sudo chmod 0754 /usr/local/libexec/autocontribute-worker
if verify_installed_assets >"${smoke_root}/unexpected-verifier-output" 2>&1; then
  fail "installed asset verification accepted a drifted helper mode"
fi
sudo chmod 0755 /usr/local/libexec/autocontribute-worker
verify_installed_assets

sudo install -d -o root -g "$service_account" -m 0750 "$config_root"
sudo install -o root -g root -m 0600 \
  "${smoke_root}/marker" "${config_root}/.autocontribute-acceptance"
config_root_created=1
printf 'storage:\n  path: /var/lib/autocontribute/state\n' >"${smoke_root}/production.yml"
sudo install -o root -g "$service_account" -m 0640 \
  "${smoke_root}/production.yml" "$production_config"

sudo install -d -o root -g "$service_account" -m 0750 "$service_home"
sudo install -o root -g root -m 0600 \
  "${smoke_root}/marker" "${service_home}/.autocontribute-acceptance"
runtime_root_created=1
sudo install -d -o "$service_account" -g "$service_account" -m 0700 "$backup_root"
sudo install -o root -g root -m 0600 \
  "${smoke_root}/marker" "${backup_root}/.autocontribute-acceptance"
backup_root_created=1
sudo systemd-tmpfiles --create /etc/tmpfiles.d/autocontribute.conf

state_image="${smoke_root}/state.ext4"
backup_image="${smoke_root}/backup.ext4"
truncate --size 2G "$state_image"
truncate --size 24G "$backup_image"
state_loop="$(sudo losetup --find --show "$state_image")"
backup_loop="$(sudo losetup --find --show "$backup_image")"
[[ "$state_loop" =~ ^/dev/loop[0-9]+$ && "$backup_loop" =~ ^/dev/loop[0-9]+$ ]] || \
  fail "losetup returned an unexpected device"
[[ "$state_loop" != "$backup_loop" ]] || fail "state and backup resolved to one loop device"
[[ "$(sudo losetup --noheadings --output BACK-FILE "$state_loop" | awk '{$1=$1; print}')" == \
  "$state_image" ]] || fail "the state loop device has the wrong backing file"
[[ "$(sudo losetup --noheadings --output BACK-FILE "$backup_loop" | awk '{$1=$1; print}')" == \
  "$backup_image" ]] || fail "the backup loop device has the wrong backing file"

sudo mkfs.ext4 -q -m 1 -N 65536 -- "$state_loop"
sudo mkfs.ext4 -q -m 0 -N 393216 -- "$backup_loop"
sudo mount -t ext4 -o rw,nodev,nosuid,noexec -- "$state_loop" "$state_root"
state_mounted=1
sudo mount -t ext4 -o rw,nodev,nosuid,noexec -- "$backup_loop" "$backup_root"
backup_mounted=1
sudo chown "$service_account:$service_account" "$state_root" "$backup_root"
sudo chmod 0700 "$state_root" "$backup_root"
sudo install -d -o "$service_account" -g "$service_account" -m 0700 \
  "${state_root}/workspaces"

sudo systemctl daemon-reload
systemd_reloaded=1
for timer in \
  autocontribute-worker.timer \
  autocontribute-health.timer \
  autocontribute-backup.timer; do
  timer_state="$(sudo systemctl is-enabled "$timer" 2>/dev/null || true)"
  [[ "$timer_state" == "disabled" ]] || fail "acceptance unexpectedly enabled $timer"
done
unset timer timer_state

run_as_service() {
  sudo -u "$service_account" /usr/bin/env -i \
    HOME="$service_home" \
    TMPDIR="${service_home}/tmp" \
    NO_COLOR=1 \
    PATH="$clean_path" \
    PYTHONUNBUFFERED=1 \
    "$@"
}

run_id="$({
  run_as_service "${current_release}/.venv/bin/python" - "$state_root" <<'PY'
import sys
from pathlib import Path

from autocontribute.store import RunStore

store = RunStore(Path(sys.argv[1]))
run = store.create_run()
store.write_artifact(run.run_id, "review-note.txt", "sealed acceptance evidence\n")
store.verify_event_chains(run_id=run.run_id)
print(run.run_id)
PY
} | tail -n 1)"
[[ "$run_id" =~ ^[0-9a-f]{16}$ ]] || fail "the seeded run ID is invalid"

if ! sudo systemctl start autocontribute-backup.service; then
  sudo journalctl --no-pager --unit autocontribute-backup.service --lines 100 >&2 || true
  fail "the hardened backup service failed"
fi
[[ "$(sudo systemctl show autocontribute-backup.service --property=Result --value)" == \
  "success" ]] || fail "the hardened backup service did not report success"

mapfile -t bundles < <(
  sudo -u "$service_account" find "$backup_root" -maxdepth 1 -type f \
    -name 'autocontribute-state-*.bundle.zip' -print | sort
)
[[ "${#bundles[@]}" -eq 1 ]] || fail "the backup service did not create exactly one bundle"
bundle="${bundles[0]}"
[[ "$(sudo stat --format=%u:%g:%a -- "$bundle")" == \
  "${service_uid}:${service_gid}:400" ]] || \
  fail "the complete bundle has unsafe ownership or mode"

recovery_parent="${backup_root}/recovery"
trusted_bundle="${recovery_parent}/trusted.bundle.zip"
corrupt_bundle="${recovery_parent}/corrupt.bundle.zip"
rejected_root="${recovery_parent}/rejected"
restored_root="${recovery_parent}/restored"
sudo -u "$service_account" install -d -m 0700 "$recovery_parent"
sudo -u "$service_account" cp -- "$bundle" "$trusted_bundle"
sudo -u "$service_account" chmod 0400 "$trusted_bundle"

run_as_service "${current_release}/.venv/bin/python" - \
  "$trusted_bundle" "$corrupt_bundle" "runs/${run_id}/review-note.txt" <<'PY'
import sys
import zipfile
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
target = sys.argv[3]
changed = False
with zipfile.ZipFile(source, "r") as source_archive:
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as output_archive:
        for member in source_archive.infolist():
            data = source_archive.read(member)
            if member.filename == target:
                data = b"tampered acceptance evidence\n"
                changed = True
            output_archive.writestr(member, data)
if not changed:
    raise SystemExit("the recovery fixture artifact was absent from the bundle")
destination.chmod(0o400)
PY

printf 'storage:\n  path: %s\n' "$rejected_root" >"${smoke_root}/rejected.yml"
printf 'storage:\n  path: %s\n' "$restored_root" >"${smoke_root}/restored.yml"
sudo install -o root -g "$service_account" -m 0640 \
  "${smoke_root}/rejected.yml" "${config_root}/rejected.yml"
sudo install -o root -g "$service_account" -m 0640 \
  "${smoke_root}/restored.yml" "${config_root}/restored.yml"

set +e
corrupt_output="$(
  run_as_service "${current_release}/.venv/bin/autocontribute" \
    state restore --complete \
    --input "$corrupt_bundle" \
    --config "${config_root}/rejected.yml" 2>&1
)"
corrupt_status=$?
set -e
[[ "$corrupt_status" -ne 0 ]] || fail "a tampered complete bundle was restored"
[[ "$corrupt_output" == *"checksum mismatch"* ]] || \
  fail "the tampered bundle did not fail at checksum verification"
if sudo -u "$service_account" test -e "$rejected_root" || \
  sudo -u "$service_account" test -L "$rejected_root"; then
  fail "a rejected restore left a promoted state root"
fi
unset corrupt_output corrupt_status

run_as_service "${current_release}/.venv/bin/autocontribute" \
  state restore --complete \
  --input "$trusted_bundle" \
  --config "${config_root}/restored.yml"
sudo -u "$service_account" test -f "${restored_root}/state.sqlite3" || \
  fail "restored SQLite state is absent"
for restored_directory in runs evaluations workspaces; do
  sudo -u "$service_account" test -d "${restored_root}/${restored_directory}" || \
    fail "the restored generation is incomplete"
done
unset restored_directory

runs_output="$(
  run_as_service "${current_release}/.venv/bin/autocontribute" \
    runs list --config "${config_root}/restored.yml"
)"
[[ "$runs_output" == *"$run_id"* ]] || fail "the restored run is not inspectable"
run_as_service "${current_release}/.venv/bin/autocontribute" \
  eval report --config "${config_root}/restored.yml" >/dev/null

run_as_service "${current_release}/.venv/bin/python" - "$restored_root" "$run_id" <<'PY'
import sys
from pathlib import Path

from autocontribute.store import RunStore

store = RunStore(Path(sys.argv[1]))
run = store.get(sys.argv[2])
if run.run_id != sys.argv[2]:
    raise SystemExit("restored run identity changed")
store.verify_event_chains(run_id=run.run_id)
artifact = store.artifact_dir(run.run_id) / "review-note.txt"
if artifact.read_text(encoding="utf-8") != "sealed acceptance evidence\n":
    raise SystemExit("restored evidence differs from the verified source")
PY

database_digest="$(
  sudo -u "$service_account" sha256sum "${restored_root}/state.sqlite3" | awk '{print $1}'
)"
artifact_digest="$(
  sudo -u "$service_account" \
    sha256sum "${restored_root}/runs/${run_id}/review-note.txt" | awk '{print $1}'
)"
set +e
existing_output="$(
  run_as_service "${current_release}/.venv/bin/autocontribute" \
    state restore --complete \
    --input "$trusted_bundle" \
    --config "${config_root}/restored.yml" 2>&1
)"
existing_status=$?
set -e
[[ "$existing_status" -ne 0 ]] || fail "restore replaced an existing state generation"
[[ "$existing_output" == *"requires an absent storage root"* ]] || \
  fail "the existing-target restore did not fail closed"
[[ "$(
  sudo -u "$service_account" sha256sum "${restored_root}/state.sqlite3" | awk '{print $1}'
)" == \
  "$database_digest" ]] || fail "failed restore changed the existing database"
[[ "$(
  sudo -u "$service_account" \
    sha256sum "${restored_root}/runs/${run_id}/review-note.txt" | awk '{print $1}'
)" == \
  "$artifact_digest" ]] || fail "failed restore changed existing evidence"

printf 'Ubuntu 24.04 deployment/recovery acceptance passed for release %s and run %s\n' \
  "$release_id" "$run_id"
