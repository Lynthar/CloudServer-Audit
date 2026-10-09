# The throwaway host for tests/mutation/run.sh: systemd as PID 1, vpssec's runtime
# dependencies, and what the cases plant into (sshd, nginx, sudo, at, python3).
# Packages a fix INSTALLS (logrotate, ufw, fail2ban) stay out: those cases start from absent.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv ca-certificates procps iproute2 jq curl tar bsdutils \
        openssh-server nginx-light sudo at python3-minimal \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
# binfmt_misc is one table for the whole host, not per container: unmasked, this
# privileged systemd clears every registration on the host (Rosetta, qemu) at
# boot and again at shutdown, as soon as any package ships a binfmt.d file.
RUN systemctl mask systemd-binfmt.service proc-sys-fs-binfmt_misc.automount \
        proc-sys-fs-binfmt_misc.mount
CMD ["/sbin/init"]
