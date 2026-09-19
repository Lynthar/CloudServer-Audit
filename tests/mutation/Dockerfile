# The throwaway host for tests/mutation/run.sh: systemd as PID 1, vpssec's runtime
# dependencies, and the daemons the cases plant defects into. Packages the fixes
# INSTALL (logrotate, ufw, fail2ban) are left out so those cases start from absent.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv ca-certificates procps iproute2 jq curl tar bsdutils \
        openssh-server nginx-light \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
