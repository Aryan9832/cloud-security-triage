#!/usr/bin/env bash
# A first-install helper. Existing installations/data are never overwritten.
set -euo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_MODE=${1:---dry-run}

usage() {
    printf '%s\n' 'Usage: bash scripts/install-linux.sh --dry-run | --stage /absolute/new/directory | --install'
}

copy_layout() {
    local stage_prefix=$1
    install -d -m 0755 "$stage_prefix/opt/cloud-triage/triage" "$stage_prefix/opt/cloud-triage/examples"
    install -d -m 0750 "$stage_prefix/etc/cloud-triage"
    install -d -m 0755 "$stage_prefix/etc/systemd/system"
    install -m 0644 "$PROJECT_DIR"/triage/*.py "$stage_prefix/opt/cloud-triage/triage/"
    install -m 0644 "$PROJECT_DIR"/examples/day*.json "$stage_prefix/opt/cloud-triage/examples/"
    install -m 0644 "$PROJECT_DIR/requirements-aws.txt" "$stage_prefix/opt/cloud-triage/"
    install -m 0640 "$PROJECT_DIR/deploy/linux/config.json" "$stage_prefix/etc/cloud-triage/config.json"
    install -m 0640 "$PROJECT_DIR/examples/owners.json" "$stage_prefix/etc/cloud-triage/owners.json"
    install -m 0644 "$PROJECT_DIR/deploy/linux/cloud-triage.service" "$stage_prefix/etc/systemd/system/"
    install -m 0644 "$PROJECT_DIR/deploy/linux/cloud-triage.timer" "$stage_prefix/etc/systemd/system/"
}

case "$INSTALL_MODE" in
    --dry-run)
        [[ $# -le 1 ]] || { usage; exit 2; }
        printf '%s\n' \
            'First-install plan (no changes):' \
            '  Require Linux, systemd, root, Python >=3.9, and python3-venv.' \
            '  Refuse existing cloud-triage account, application, configuration, unit files, or state.' \
            '  Copy application to /opt/cloud-triage and create a Python virtual environment.' \
            '  Create a non-login cloud-triage service account.' \
            '  Install fixture-mode configuration in /etc/cloud-triage (root-owned).' \
            '  Create private writable state in /var/lib/cloud-triage.' \
            '  Install the service/timer and reload systemd; leave both stopped/disabled.'
        ;;
    --stage)
        [[ $# -eq 2 && "$2" == /* && "$2" != / && ! -e "$2" && ! -L "$2" ]] || {
            printf '%s\n' 'Stage requires an absolute, new directory path.' >&2; exit 2;
        }
        mkdir -m 0700 -- "$2"
        copy_layout "$2"
        printf '%s\n' "Staged files under $2. No users, virtual environment, services, or timers were created."
        ;;
    --install)
        [[ $# -eq 1 ]] || { usage; exit 2; }
        [[ $(uname -s) == Linux && $EUID -eq 0 && -d /run/systemd/system ]] || {
            printf '%s\n' 'Install requires root on a Linux host booted with systemd.' >&2; exit 1;
        }
        for install_tool in python3 systemctl useradd getent install chown; do
            command -v "$install_tool" >/dev/null || { printf 'Missing tool: %s\n' "$install_tool" >&2; exit 1; }
        done
        python3 -c 'import sys, venv, ensurepip; assert sys.version_info >= (3, 9), "Python >=3.9 required"'
        for install_target in /opt/cloud-triage /etc/cloud-triage /var/lib/cloud-triage \
            /etc/systemd/system/cloud-triage.service /etc/systemd/system/cloud-triage.timer; do
            [[ ! -e "$install_target" && ! -L "$install_target" ]] || {
                printf 'Refusing to overwrite existing target: %s\n' "$install_target" >&2; exit 1;
            }
        done
        if getent passwd cloud-triage >/dev/null || getent group cloud-triage >/dev/null; then
            printf '%s\n' 'The cloud-triage account/group already exists. Inspect the existing installation first.' >&2
            exit 1
        fi
        trap 'printf "%s\n" "Install interrupted. Inspect the explicit target paths before retrying; existing files were preserved." >&2' ERR
        copy_layout ''
        python3 -m venv /opt/cloud-triage/venv
        useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin cloud-triage
        chown root:cloud-triage /etc/cloud-triage /etc/cloud-triage/config.json /etc/cloud-triage/owners.json
        install -d -o cloud-triage -g cloud-triage -m 0700 /var/lib/cloud-triage
        systemctl daemon-reload
        printf '%s\n' 'Installed in fixture mode. Start once: sudo systemctl start cloud-triage.service' \
            'After checking the report, schedule it: sudo systemctl enable --now cloud-triage.timer'
        ;;
    *) usage; exit 2 ;;
esac
