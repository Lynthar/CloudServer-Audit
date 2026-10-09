#!/usr/bin/env bats
# ssh.harden_algorithms removes what the audit calls weak from sshd's own
# defaults instead of replacing them with a fixed list, which dropped the
# post-quantum hybrid KEX that Debian 12/13 and Ubuntu 24.04+ negotiate first.

load helpers.bash

setup() {
    _vpssec_load
    i18n_load en_US
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    etc=$(_vpssec_fake_etc)
    SSH_CONFIG="$etc/ssh/sshd_config"
    SSH_DROPIN_DIR="$etc/ssh/sshd_config.d"
    SSH_HARDENING_DROPIN="$SSH_DROPIN_DIR/00-vpssec-hardening.conf"
    mkdir -p "$SSH_DROPIN_DIR"
    export TMPDIR="$BATS_TEST_TMPDIR"
    export VPSSEC_TEST_DROPIN="$SSH_HARDENING_DROPIN"
    _vpssec_stub systemctl
    # sshd -T: these defaults, as OpenSSH 7.5+ applies a drop-in list that
    # starts with "-" (each pattern removed) or not (the list replaces them).
    _vpssec_stub_script sshd <<'SH'
[[ "$1" == -T ]] || exit 0
declare -A def=(
    [ciphers]="chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com,3des-cbc,arcfour256,blowfish-cbc"
    [macs]="umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha1,hmac-md5-96"
    [kexalgorithms]="mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1"
)
for k in ciphers macs kexalgorithms; do
    list="${def[$k]}"
    set=$(grep -i "^$k " "$VPSSEC_TEST_DROPIN" 2>/dev/null | awk '{ print $2; exit }')
    if [[ "$set" == -* ]]; then
        IFS=, read -ra pats <<<"${set#-}"
        IFS=, read -ra algs <<<"$list"
        list=""
        for a in "${algs[@]}"; do
            keep=1
            for p in "${pats[@]}"; do [[ "$a" == $p ]] && keep=0; done
            (( keep )) && list+="${list:+,}$a"
        done
    elif [[ -n "$set" ]]; then
        list="$set"
    fi
    echo "$k $list"
done
SH
}

_offered() { sshd -T | awk -v k="$1" '$1 == k { print $2 }'; }

@test "harden: every weak algorithm goes, every other default stays" {
    [ -n "$(_ssh_weak_algorithms)" ]
    _ssh_fix_harden_algorithms
    [ -z "$(_ssh_weak_algorithms)" ]
    [ "$(_offered kexalgorithms)" = "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256" ]
    [ "$(_offered macs)" = "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-256" ]
    [ "$(_offered ciphers)" = "chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com" ]
}

@test "harden: other settings in the drop-in are kept" {
    printf 'MaxAuthTries 3\nMACs hmac-sha1\n' > "$SSH_HARDENING_DROPIN"
    _ssh_fix_harden_algorithms
    grep -qx 'MaxAuthTries 3' "$SSH_HARDENING_DROPIN"
    [ -z "$(_ssh_weak_algorithms)" ]
}
