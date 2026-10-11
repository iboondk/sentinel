#!/usr/bin/env bash
# Sentinel: Linux hardening checks with an idempotent apply mode.
# See hardening/CHECKLIST.md for the rationale and manual verify commands.
#
# Usage: harden.sh [--check|--apply] [--only ID] [--reload]
#   --check     report only (default). Changes nothing.
#   --apply     fix each FAIL. A changed file is backed up once to <file>.sentinel.bak.
#   --only ID   run one check, e.g. SSH-01.
#   --reload    with --apply on a real host (SENTINEL_ROOT empty): run
#               "sysctl -p" and reload sshd after changes. Never run otherwise.
# Exit: 0 no FAIL remains, 1 a FAIL remains, 2 usage error.
# SENTINEL_ROOT prefixes every path so tests can run against a fixture tree.
# Compatible with macOS bash 3.2: no associative arrays, no sed -i, no mapfile.
# Edits are written to a temp file in the same directory and moved into place.

set -u

ROOT="${SENTINEL_ROOT:-}"
SYSCTL_REL="/etc/sysctl.d/99-sentinel.conf"
ALL_IDS="SSH-01 SSH-02 SSH-03 SSH-04 SYS-01 SYS-02 SYS-03 SYS-04 AUTH-01 PERM-01 PERM-02"

MODE_GIVEN=""
ONLY=""
ONLY_GIVEN=""
RELOAD=0
CREATED=" "
CHANGED_SSH=0
CHANGED_SYS=0
RESULT=""
DESC=""

usage() {
  cat <<'EOF'
Usage: harden.sh [--check|--apply] [--only ID] [--reload]

  --check      report PASS/FAIL for each check (default); changes nothing
  --apply      fix FAIL checks; each changed file is backed up once to <file>.sentinel.bak
  --only ID    run a single check: SSH-01 SSH-02 SSH-03 SSH-04 SYS-01 SYS-02
               SYS-03 SYS-04 AUTH-01 PERM-01 PERM-02
  --reload     with --apply and an empty SENTINEL_ROOT: run sysctl -p and reload sshd
  -h, --help   show this help

Exit codes: 0 no FAIL remains, 1 a FAIL remains, 2 usage error.
SENTINEL_ROOT=<dir> prefixes every path (the test fixtures use it).
EOF
}

usage_error() {
  printf 'harden.sh: %s\n' "$1" >&2
  usage >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check|--apply)
      if [ -n "$MODE_GIVEN" ] && [ "$MODE_GIVEN" != "${1#--}" ]; then
        usage_error "--check and --apply cannot be combined"
      fi
      MODE_GIVEN="${1#--}"
      shift
      ;;
    --only)
      [ $# -ge 2 ] || usage_error "--only needs a check ID"
      ONLY="$2"
      ONLY_GIVEN=1
      shift 2
      ;;
    --only=*)
      ONLY="${1#--only=}"
      ONLY_GIVEN=1
      shift
      ;;
    --reload)
      RELOAD=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage_error "unknown argument: $1"
      ;;
  esac
done

MODE="${MODE_GIVEN:-check}"

if [ -n "$ONLY_GIVEN" ]; then
  case " $ALL_IDS " in
    *" $ONLY "*) IDS="$ONLY" ;;
    *) usage_error "unknown check ID: '$ONLY'" ;;
  esac
else
  IDS="$ALL_IDS"
fi

if [ "$MODE" = apply ] && [ -z "$ROOT" ] && [ "$(id -u)" != 0 ]; then
  printf 'harden.sh: --apply on this host requires root (EUID 0). Run it with sudo, or set SENTINEL_ROOT for a fixture tree.\n' >&2
  exit 2
fi

# File mode as octal digits (e.g. 640). GNU stat first, then BSD/macOS stat.
get_mode() {
  stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null
}

# Print every active (non-comment) value of KEY in FILE, one per line.
# Keys match case-insensitively. "=" and whitespace both separate key and value.
directive_values() {
  awk -v key="$2" '
    /^[[:space:]]*#/ { next }
    { gsub(/=/, " ") }
    NF >= 2 && tolower($1) == tolower(key) {
      v = $2
      for (i = 3; i <= NF; i++) v = v " " $i
      print v
    }
  ' "$1"
}

# Read values on stdin. Print: none (no values), ok (all compliant), or bad.
# kind "eq": every value equals EXPECT (case-insensitive).
# kind "le": every value is an integer <= EXPECT.
directive_verdict() {
  kind="$1"
  expect="$2"
  n=0
  bad=0
  while IFS= read -r v || [ -n "$v" ]; do
    n=$((n + 1))
    case "$kind" in
      eq)
        lv=$(printf '%s' "$v" | tr 'A-Z' 'a-z')
        le=$(printf '%s' "$expect" | tr 'A-Z' 'a-z')
        if [ "$lv" != "$le" ]; then bad=1; fi
        ;;
      le)
        case "$v" in
          ''|*[!0-9]*) bad=1 ;;
          *) if [ "$v" -gt "$expect" ]; then bad=1; fi ;;
        esac
        ;;
    esac
  done
  if [ "$n" -eq 0 ]; then
    echo none
  elif [ "$bad" -eq 1 ]; then
    echo bad
  else
    echo ok
  fi
}

# Copy FILE to FILE.sentinel.bak once (mode 600). Files created in this run are skipped.
backup_once() {
  case "$CREATED" in
    *" $1 "*) return 0 ;;
  esac
  if [ ! -e "$1.sentinel.bak" ]; then
    cp -p "$1" "$1.sentinel.bak" || return 1
    chmod 600 "$1.sentinel.bak" || return 1
  fi
  return 0
}

# Replace every active setting of KEY with LINE. Insert LINE when none exists:
# at the top ("prepend", so it wins in sshd) or at the end ("append").
# The result goes to a temp file in the same directory, keeps the original mode,
# then replaces the file with mv.
set_directive() {
  sd_file="$1"
  sd_key="$2"
  sd_line="$3"
  sd_pos="$4"
  sd_count=$(directive_values "$sd_file" "$sd_key" | awk 'END { print NR }')
  backup_once "$sd_file" || return 1
  sd_tmp=$(mktemp "$sd_file.sentinel.XXXXXX") || return 1
  if ! awk -v key="$sd_key" -v newline="$sd_line" -v pos="$sd_pos" -v count="$sd_count" '
    function is_setting(l,   t, n, parts) {
      t = l
      gsub(/=/, " ", t)
      sub(/^[[:space:]]+/, "", t)
      if (t ~ /^#/) return 0
      n = split(t, parts, /[[:space:]]+/)
      if (n < 2) return 0
      return tolower(parts[1]) == tolower(key)
    }
    BEGIN { if (pos == "prepend" && count + 0 == 0) print newline }
    {
      if (is_setting($0)) {
        if (!done) print newline
        done = 1
        next
      }
      print
    }
    END { if (pos == "append" && count + 0 == 0) print newline }
  ' "$sd_file" > "$sd_tmp"; then
    rm -f "$sd_tmp"
    return 1
  fi
  sd_mode=$(get_mode "$sd_file")
  case "$sd_mode" in
    ''|*[!0-7]*) ;;
    *) chmod "$sd_mode" "$sd_tmp" ;;
  esac
  mv "$sd_tmp" "$sd_file" || { rm -f "$sd_tmp"; return 1; }
  return 0
}

# Create an empty sysctl drop-in with a header. Records it so no backup is taken.
create_sysctl_file() {
  mkdir -p "$(dirname "$1")" || return 1
  printf '%s\n' "# Managed by Sentinel hardening/harden.sh" > "$1" || return 1
  CREATED="$CREATED$1 "
  return 0
}

show_values() {
  if [ -z "$1" ]; then
    echo "not set"
  else
    printf '%s' "$1" | tr '\n' ' '
  fi
}

mark_changed() {
  case "$1" in
    /etc/ssh/*) CHANGED_SSH=1 ;;
    /etc/sysctl.d/*) CHANGED_SYS=1 ;;
  esac
}

# check_directive ID REL KEY KIND EXPECT LINE POS WHAT MAY_CREATE
# Sets RESULT (PASS, FAIL or FIXED) and DESC.
check_directive() {
  cd_id="$1"
  cd_rel="$2"
  cd_key="$3"
  cd_kind="$4"
  cd_expect="$5"
  cd_line="$6"
  cd_pos="$7"
  cd_what="$8"
  cd_create="$9"
  cd_file="$ROOT$cd_rel"

  if [ ! -f "$cd_file" ]; then
    if [ "$MODE" = apply ] && [ "$cd_create" = yes ]; then
      if ! create_sysctl_file "$cd_file"; then
        RESULT=FAIL
        DESC="$cd_what ($cd_rel could not be created)"
        return
      fi
    else
      RESULT=FAIL
      DESC="$cd_what ($cd_rel missing)"
      return
    fi
  fi

  cd_vals=$(directive_values "$cd_file" "$cd_key")
  cd_verdict=$(printf '%s' "$cd_vals" | directive_verdict "$cd_kind" "$cd_expect")
  if [ "$cd_verdict" = ok ]; then
    RESULT=PASS
    DESC="$cd_what [found: $(show_values "$cd_vals")]"
    return
  fi

  RESULT=FAIL
  DESC="$cd_what [found: $(show_values "$cd_vals")]"
  if [ "$MODE" != apply ]; then
    return
  fi

  if ! set_directive "$cd_file" "$cd_key" "$cd_line" "$cd_pos"; then
    DESC="$cd_what [found: $(show_values "$cd_vals")] (could not write $cd_rel)"
    return
  fi
  cd_vals=$(directive_values "$cd_file" "$cd_key")
  cd_verdict=$(printf '%s' "$cd_vals" | directive_verdict "$cd_kind" "$cd_expect")
  if [ "$cd_verdict" = ok ]; then
    RESULT=FIXED
    DESC="$cd_what [now: $(show_values "$cd_vals")]"
    mark_changed "$cd_rel"
  else
    DESC="$cd_what [found: $(show_values "$cd_vals")] (fix did not take effect)"
  fi
}

# perm_ok RULE MODE_DIGITS. RULE "subset640": no bits outside 640.
# RULE "exact644": mode is exactly 644.
perm_ok() {
  pv=$((8#$2))
  case "$1" in
    subset640) [ $((pv & $((8#137)))) -eq 0 ] ;;
    exact644) [ "$pv" -eq $((8#644)) ] ;;
    *) return 1 ;;
  esac
}

# check_perm ID REL RULE TARGET_MODE WHAT
check_perm() {
  cp_rel="$2"
  cp_rule="$3"
  cp_target="$4"
  cp_what="$5"
  cp_file="$ROOT$cp_rel"

  if [ ! -e "$cp_file" ]; then
    RESULT=FAIL
    DESC="$cp_what ($cp_rel missing)"
    return
  fi
  cp_mode=$(get_mode "$cp_file")
  case "$cp_mode" in
    ''|*[!0-7]*)
      RESULT=FAIL
      DESC="$cp_what (cannot read mode of $cp_rel)"
      return
      ;;
  esac
  if perm_ok "$cp_rule" "$cp_mode"; then
    RESULT=PASS
    DESC="$cp_what [found: $cp_mode]"
    return
  fi

  RESULT=FAIL
  DESC="$cp_what [found: $cp_mode]"
  if [ "$MODE" != apply ]; then
    return
  fi
  if ! backup_once "$cp_file"; then
    DESC="$cp_what [found: $cp_mode] (could not back up $cp_rel)"
    return
  fi
  if ! chmod "$cp_target" "$cp_file"; then
    DESC="$cp_what [found: $cp_mode] (could not chmod $cp_rel)"
    return
  fi
  cp_mode=$(get_mode "$cp_file")
  if perm_ok "$cp_rule" "$cp_mode"; then
    RESULT=FIXED
    DESC="$cp_what [now: $cp_mode]"
  else
    DESC="$cp_what [found: $cp_mode] (fix did not take effect)"
  fi
}

run_check() {
  case "$1" in
    SSH-01)
      check_directive SSH-01 /etc/ssh/sshd_config PermitRootLogin eq no \
        "PermitRootLogin no" prepend "PermitRootLogin must be no" no ;;
    SSH-02)
      check_directive SSH-02 /etc/ssh/sshd_config PasswordAuthentication eq no \
        "PasswordAuthentication no" prepend "PasswordAuthentication must be no" no ;;
    SSH-03)
      check_directive SSH-03 /etc/ssh/sshd_config X11Forwarding eq no \
        "X11Forwarding no" prepend "X11Forwarding must be no" no ;;
    SSH-04)
      check_directive SSH-04 /etc/ssh/sshd_config MaxAuthTries le 4 \
        "MaxAuthTries 4" prepend "MaxAuthTries must be 4 or less" no ;;
    SYS-01)
      check_directive SYS-01 "$SYSCTL_REL" net.ipv4.ip_forward eq 0 \
        "net.ipv4.ip_forward = 0" append "net.ipv4.ip_forward must be 0" yes ;;
    SYS-02)
      check_directive SYS-02 "$SYSCTL_REL" net.ipv4.conf.all.accept_redirects eq 0 \
        "net.ipv4.conf.all.accept_redirects = 0" append "net.ipv4.conf.all.accept_redirects must be 0" yes ;;
    SYS-03)
      check_directive SYS-03 "$SYSCTL_REL" kernel.randomize_va_space eq 2 \
        "kernel.randomize_va_space = 2" append "kernel.randomize_va_space must be 2" yes ;;
    SYS-04)
      check_directive SYS-04 "$SYSCTL_REL" net.ipv4.tcp_syncookies eq 1 \
        "net.ipv4.tcp_syncookies = 1" append "net.ipv4.tcp_syncookies must be 1" yes ;;
    AUTH-01)
      check_directive AUTH-01 /etc/login.defs PASS_MAX_DAYS le 90 \
        "PASS_MAX_DAYS 90" append "PASS_MAX_DAYS must be 90 or less" no ;;
    PERM-01)
      check_perm PERM-01 /etc/shadow subset640 640 "/etc/shadow mode 640 or stricter" ;;
    PERM-02)
      check_perm PERM-02 /etc/passwd exact644 644 "/etc/passwd mode must be 644" ;;
  esac
}

reload_services() {
  if [ "$CHANGED_SYS" -eq 1 ] && command -v sysctl >/dev/null 2>&1; then
    if ! sysctl -p "$SYSCTL_REL" >/dev/null 2>&1; then
      printf 'note: sysctl -p %s failed\n' "$SYSCTL_REL" >&2
    fi
  fi
  if [ "$CHANGED_SSH" -eq 1 ] && command -v sshd >/dev/null 2>&1 && command -v systemctl >/dev/null 2>&1; then
    if sshd -t >/dev/null 2>&1; then
      if ! systemctl reload sshd >/dev/null 2>&1 && ! systemctl reload ssh >/dev/null 2>&1; then
        printf 'note: could not reload sshd\n' >&2
      fi
    else
      printf 'note: sshd -t failed, sshd was not reloaded\n' >&2
    fi
  fi
}

TOTAL=0
N_PASS=0
N_FIXED=0
N_FAIL=0
for check_id in $IDS; do
  RESULT=""
  DESC=""
  run_check "$check_id"
  printf '%s %s %s\n' "$RESULT" "$check_id" "$DESC"
  TOTAL=$((TOTAL + 1))
  case "$RESULT" in
    PASS) N_PASS=$((N_PASS + 1)) ;;
    FIXED) N_FIXED=$((N_FIXED + 1)) ;;
    *) N_FAIL=$((N_FAIL + 1)) ;;
  esac
done

if [ "$MODE" = apply ] && [ "$RELOAD" -eq 1 ]; then
  if [ -n "$ROOT" ]; then
    printf 'note: --reload ignored because SENTINEL_ROOT is set\n' >&2
  else
    reload_services
  fi
fi

printf 'SUMMARY mode=%s checks=%d pass=%d fixed=%d fail=%d\n' "$MODE" "$TOTAL" "$N_PASS" "$N_FIXED" "$N_FAIL"

if [ "$N_FAIL" -gt 0 ]; then
  exit 1
fi
exit 0
