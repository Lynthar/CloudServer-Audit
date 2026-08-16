#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Fix safety classification and score categories
# Copyright (c) 2024

# --- Fix safety: SAFE = auto-applied, CONFIRM = warned, RISKY = explicit
# confirmation with safeguards, ALERT_ONLY = never auto-fixed. A SAFE fix may
# neither restart a service nor prompt. Membership notes: see the design notes ---

# Safe fixes - can be auto-applied in guide mode
declare -gA FIX_SAFE=(
    # configure_ssh_jail / enable_ssh_jail stay CONFIRM: the drop-in still
    # overrides an operator's own bantime/maxretry/ignoreip.
    ["fail2ban.install"]="true"
    ["fail2ban.enable_service"]="true"

    # install/enable_unattended stay CONFIRM: they turn on unattended
    # package installation.

    # enable_apparmor / disable_unused stay CONFIRM: both can break a
    # running service.

    # Logging - logging configuration
    ["logging.enable_persistent_journal"]="true"
    ["logging.setup_logrotate"]="true"
    ["logging.install_auditd"]="true"
    ["logging.enable_auditd"]="true"
    ["logging.setup_audit_rules"]="true"

    # harden_ipv6 stays CONFIRM: disabling accept_ra drops the SLAAC route on
    # an RA-configured host. harden_kernel stays CONFIRM: it disables
    # unprivileged user namespaces, breaking rootless containers and sandboxes.
    ["kernel.enable_aslr"]="true"
    ["kernel.disable_core_dump"]="true"

    # Filesystem - permission fixes
    ["filesystem.fix_sensitive_perms"]="true"
    ["filesystem.fix_umask"]="true"

    # SSH - safe settings that don't affect access
    ["ssh.enable_pubkey"]="true"
    ["ssh.disable_empty_password"]="true"
    ["ssh.set_max_auth_tries"]="true"
    ["ssh.set_login_grace_time"]="true"
    ["ssh.disable_x11_forwarding"]="true"

    # UFW - adding rules only
    ["ufw.install"]="true"
    ["ufw.allow_ssh"]="true"

    # enable_live_restore stays CONFIRM: it needs a docker restart, which
    # pauses every running container.

    # Template generation only
    ["docker.generate_proxy_template"]="true"
    ["cloudflared.generate_config"]="true"
    ["cloudflared.setup_service"]="true"
    ["backup.generate_templates"]="true"
    ["alerts.setup_config"]="true"
    # No alerts.generate_templates: no check emits it as a fix_id. Template
    # generation is a step inside alerts.setup_config.

    # set_timezone stays CONFIRM: it prompts, and it is offered on passing
    # checks too, so auto-applying would stall a select-all run.
    ["timezone.enable_ntp"]="true"
    # No timezone.sync_time: no check emits it. The actionable case is
    # covered by timezone.enable_ntp.
    ["timezone.set_rtc_utc"]="true"
    ["timezone.set_locale"]="true"

    # Webapp - safe header configurations
    ["webapp.nginx_server_tokens"]="true"
    ["webapp.nginx_security_headers"]="true"
)

# Fixes requiring confirmation - medium risk
declare -gA FIX_CONFIRM=(
    # Network params may conflict with Docker/containers. On SLAAC hosts the
    # IPv6 RA params (accept_ra/autoconf/...) are skipped automatically to
    # preserve connectivity, but warn anyway.
    ["kernel.harden_network"]="May affect container networking (Docker/LXC); IPv6 RA settings are skipped on SLAAC hosts to preserve connectivity"

    # Disables unprivileged user namespaces (breaks Docker rootless / podman /
    # snap / Chrome sandbox) and restricts SysRq — review before applying.
    ["kernel.harden_kernel"]="Disables unprivileged user namespaces (breaks Docker rootless / podman / Chrome sandbox) and restricts SysRq"

    # IPv6 RA hardening can drop the IPv6 default route/address on hosts that
    # configure IPv6 via Router Advertisements (SLAAC) — the fix detects RA
    # and skips those params, but warn anyway.
    ["kernel.harden_ipv6"]="May drop IPv6 connectivity on hosts that obtain their address/route via Router Advertisements (SLAAC)"

    # SELinux - can cause service issues if policies not configured
    ["baseline.selinux_set_enforcing"]="May cause service denials if SELinux policies not configured properly"

    # AppArmor enforce loads all packaged profiles -> can confine a running service
    ["baseline.enable_apparmor"]="Enforces all installed AppArmor profiles immediately; may cause denials against a running service"

    # Stopping "unused" services can disrupt ones the operator relies on
    ["baseline.disable_unused"]="Stops/disables services flagged as unused (e.g. avahi/cups); review before applying"

    # Overrides the operator's sshd-jail settings via a drop-in, without
    # replacing their files (enable_ssh_jail is the same writer)
    ["fail2ban.configure_ssh_jail"]="Writes /etc/fail2ban/jail.d/99-vpssec-sshd.local; existing files are kept, but it overrides the bantime/maxretry/ignoreip you set in jail.local or jail.d/*.conf for the sshd jail"
    ["fail2ban.enable_ssh_jail"]="Writes /etc/fail2ban/jail.d/99-vpssec-sshd.local; existing files are kept, but it overrides the bantime/maxretry/ignoreip you set in jail.local or jail.d/*.conf for the sshd jail"

    # Enables unattended, automatic installation of (security) updates
    ["update.install_unattended"]="Installs and enables automatic unattended security updates"
    ["update.enable_unattended"]="Enables automatic unattended installation of security updates"

    # Requires service restart
    ["docker.enable_no_new_privileges"]="Requires Docker daemon restart"
    ["docker.enable_live_restore"]="Requires a Docker daemon restart, which briefly pauses every running container"

    # Interactive: prompts for a timezone, and is offered on hosts whose
    # timezone is already correct so the operator can change it on purpose.
    ["timezone.set_timezone"]="Prompts for a new system timezone; log timestamps and cron schedules shift with it"

    # Modifies web server config
    ["nginx.add_catchall"]="Modifies Nginx configuration"

    # Could break old SSH clients
    ["ssh.harden_algorithms"]="May break connections from older SSH clients"

    # Webapp - SSL changes may affect connectivity
    ["webapp.nginx_ssl_protocols"]="May break old browser/client connections"
    ["webapp.nginx_ssl_ciphers"]="May break old browser/client connections"
    ["webapp.nginx_hsts"]="Once enabled, browsers will refuse HTTP"
)

# Risky fixes - requires safeguards
declare -gA FIX_RISKY=(
    # Can lock user out of SSH
    ["ssh.disable_password_auth"]="Can lock you out if SSH key not configured properly"
    ["ssh.disable_root_login"]="Can lock you out if no admin user exists"

    # Can lock user out of server
    ["ufw.enable"]="Can lock you out if SSH not allowed"

    # RISKY, not CONFIRM: honouring --yes on a deny-all flip is unsafe.
    ["ufw.set_default_deny"]="Flips the firewall to deny-all inbound; can drop running services not explicitly allowed, and can lock you out if the SSH rule is wrong"

    # Can break system packages
    ["update.apply_security"]="May break system packages or services"
)

# Alert-only - no auto-fix available
declare -gA FIX_ALERT_ONLY=(
    # Require manual review and decision
    ["docker.privileged_containers"]="Container configuration requires manual review"
    ["docker.exposed_ports"]="Port exposure is an architecture decision"
    ["docker.all_root_containers"]="Container user requires Dockerfile changes"
    ["docker.some_root_containers"]="Container user requires Dockerfile changes"
    ["docker.containers_with_caps"]="Container capabilities require manual review"
    ["docker.sock_perms_loose"]="Changing socket perms can break running tooling; review users in the docker group first"
    ["docker.seccomp_unconfined"]="Reverting seccomp=unconfined requires understanding why it was set"
    ["docker.userns_not_enabled"]="Enabling userns-remap changes storage paths and breaks some tooling"
    ["docker.host_network_used"]="Each container with --network=host needs case-by-case review; removing it may break the container's intended function"
    ["docker.secrets_in_env"]="Credentials must be rotated externally; vpssec cannot mutate running container environments safely"
    ["docker.unlimited_memory"]="Memory limits must be set at container start time; vpssec will not restart running containers"
    ["docker.default_bridge_icc_enabled"]="Changing daemon ICC setting restarts dockerd and disconnects containers"

    # Filesystem - require manual review
    ["filesystem.suspicious_suid"]="Review and remove SUID bit if not needed"
    ["filesystem.suspicious_sgid"]="Review and remove SGID bit if not needed"
    ["filesystem.world_writable"]="Review and fix permissions manually"
    ["filesystem.no_owner"]="Review and assign ownership manually"
    ["filesystem.tmp_not_separate"]="Requires partition changes"
    ["filesystem.tmp_mount_missing_opts"]="Requires fstab modification"

    # SSH - no auto-fix defined
    ["ssh.no_admin_user"]="Create admin user manually before disabling root"
    ["ssh.admin_no_key"]="Add SSH key manually"
    ["ssh.authkeys_permissions"]="Fix permissions manually"

    # Update - APT lock
    ["update.apt_locked"]="Wait for other process or remove lock manually"

    # Logging - info only
    ["logging.ssh_many_failures"]="Consider fail2ban or firewall rules"
    ["logging.ssh_some_failures"]="Monitor for brute force attempts"
    ["logging.logrotate_missing"]="Add logrotate configuration manually"

    # Cloudflared
    ["cloudflared.service_inactive"]="Start service manually"
    ["cloudflared.config_issues"]="Review configuration manually"
    ["cloudflared.no_tunnels"]="Create tunnel: cloudflared tunnel create"

    # Cloud - all require manual review
    ["cloud.agents_found"]="Review if monitoring agents are needed"
    ["cloud.suspicious_agents"]="Investigate unknown agent processes"

    # SELinux - requires reboot
    ["baseline.selinux_enable"]="Enabling SELinux requires system reboot and may cause service issues"

    # Users - ALL are alert-only, NEVER auto-modify users
    ["users.uid0_found"]="CRITICAL: Review UID 0 accounts - may be backdoors"
    ["users.empty_password"]="CRITICAL: Set passwords or lock accounts"
    ["users.system_with_shell"]="Review if shell access is needed"
    ["users.recent_users"]="Verify recently created users"
    ["users.ssh_keys_perms"]="Fix SSH key file permissions"
    ["users.suspicious_names"]="Review suspicious usernames"
    ["users.unusual_home"]="Review unusual home directories"

    # Malware - ALL are alert-only, NEVER auto-remove malware
    ["malware.hidden_processes"]="CRITICAL: System may be compromised by rootkit"
    ["malware.hidden_ports"]="CRITICAL: Investigate hidden network ports"
    ["malware.ld_preload"]="CRITICAL: LD_PRELOAD hijacking detected"
    ["malware.ld_so_preload"]="CRITICAL: Library injection detected"
    ["malware.suspicious_lkm"]="CRITICAL: Kernel module anomaly detected"
    ["malware.crypto_miner"]="Kill mining processes and investigate"
    ["malware.mining_pool_connection"]="Block mining pool and remove malware"
    ["malware.cpu_anomaly"]="Investigate high CPU processes"
    ["malware.webshell"]="Remove webshell and investigate access logs"
    ["malware.deleted_binary"]="CRITICAL: Investigate deleted binary process"
    ["malware.memfd_execution"]="CRITICAL: Fileless malware detected"
    ["malware.suspicious_path"]="Investigate processes from /tmp or /dev/shm"
    ["malware.reverse_shell"]="CRITICAL: Reverse shell detected"
    ["malware.c2_connection"]="Block suspicious outbound connections"
    ["malware.unusual_outbound"]="Review unusual connection patterns"

    # Webapp - some require manual configuration
    ["webapp.nginx_directory_listing"]="Disable autoindex in Nginx config"
    ["webapp.apache_server_signature"]="Configure Apache security settings"
    ["webapp.apache_server_tokens"]="Configure Apache security settings"
    ["webapp.apache_trace"]="Disable TRACE method in Apache"
    ["webapp.apache_directory_index"]="Disable directory indexing in Apache"
    ["webapp.apache_modules"]="Review and disable unnecessary modules"
    ["webapp.php_security"]="Update php.ini security settings"
    ["webapp.php_dangerous_functions"]="Add dangerous functions to disable_functions"
    ["webapp.php_session"]="Update PHP session security settings"
    ["webapp.php_open_basedir"]="Configure open_basedir restriction"
    ["webapp.ssl_cert_expiry"]="Renew SSL certificates"
    ["webapp.sensitive_files"]="Remove or protect sensitive files"
    ["webapp.backup_files"]="Remove backup files from web root"

    # === Review-only findings: their handlers print guidance and return 1
    # without mutating anything, so they are shown but never auto-fixed. ===
    ["ssh.configure_access_control"]="Restrict access with AllowUsers/AllowGroups manually (wrong values can lock you out)"
    ["filesystem.review_caps"]="Review file capabilities; remove if not needed"
    ["ufw.review_rules"]="Review and tighten overly-permissive firewall rules manually"
    ["users.nopasswd_sudo"]="Review NOPASSWD sudoers entries manually (do not auto-modify sudoers)"
    ["users.history"]="Shell history hardening is an operator preference"
    ["users.password_policy"]="Tune password policy in /etc/login.defs manually"
    ["users.pwquality"]="Install/configure libpam-pwquality manually"
)

# Fixes that run confirm_critical themselves, at a more precise point than the
# engine can. execute_fix skips its central gate for these to avoid a double
# prompt. Removing a module's confirm_critical means removing it here too.
declare -gA FIX_SELF_CONFIRMED=(
    ["ssh.disable_password_auth"]="true"        # confirm_critical after SSH-key precondition (modules/ssh.sh)
    ["ssh.disable_root_login"]="true"           # confirm_critical after admin-user precondition (modules/ssh.sh)
    ["ufw.enable"]="true"                        # confirm_critical after showing current rules (modules/ufw.sh)
    ["docker.enable_no_new_privileges"]="true"  # confirm_critical before daemon restart (modules/docker.sh)
    ["docker.enable_live_restore"]="true"       # same writer, same confirm_critical (modules/docker.sh)
)

# Fixes that CANNOT resolve the finding they hang off. They still return 0;
# execute_fix skips the completion record and prints the value as the manual
# step. Membership claims the fix's REACH, always (see the design notes).
declare -gA FIX_TEMPLATE_ONLY=(
    ["docker.generate_proxy_template"]="A reverse-proxy template was written for you to review and deploy; the ports stay exposed until you do"
    ["cloudflared.generate_config"]="A tunnel config template was written; copy it to /etc/cloudflared and create the tunnel to finish"
    ["backup.generate_templates"]="Backup script templates were written; no backup tool is installed and nothing is scheduled yet"
    ["alerts.setup_config"]="The alert config and monitor scripts were written; schedule them and set a webhook to start receiving alerts"
    ["webapp.nginx_ssl_protocols"]="A hardened SSL snippet was written to nginx snippets/; it does nothing until you include it in your server block"
    ["webapp.nginx_ssl_ciphers"]="A hardened SSL snippet was written to nginx snippets/; it does nothing until you include it in your server block"
    ["webapp.nginx_hsts"]="An HSTS template was written with the header commented out; uncomment it in your HTTPS server blocks once you are sure every site is HTTPS-only"
)

# --- Score categories. The score measures configuration posture, so
# heuristic IOCs, tool prerequisites and operator preferences are info
# (shown, never scored). Full rules: see the design notes ---

declare -gA CHECK_SCORE_CATEGORY=(
    # === SSH Module - required (core security) ===
    ["ssh.password_auth_enabled"]="required"
    ["ssh.password_auth_disabled"]="required"
    ["ssh.root_login_enabled"]="required"
    ["ssh.root_login_disabled"]="required"
    ["ssh.pubkey_enabled"]="required"
    ["ssh.pubkey_disabled"]="required"
    ["ssh.admin_user_exists"]="required"
    ["ssh.no_admin_user"]="required"
    ["ssh.empty_password_allowed"]="required"
    ["ssh.empty_password_denied"]="required"
    ["ssh.admin_no_key"]="recommended"
    ["ssh.authkeys_permissions"]="recommended"
    ["ssh.max_auth_tries_ok"]="info"
    ["ssh.max_auth_tries_high"]="info"
    ["ssh.login_grace_time_ok"]="info"
    ["ssh.login_grace_time_long"]="info"
    ["ssh.x11_forwarding_disabled"]="info"
    ["ssh.x11_forwarding_enabled"]="info"
    ["ssh.weak_algorithms"]="optional"
    ["ssh.algorithms_ok"]="optional"
    # SSH-7408 additional hardening (Lynis cross-check) - info only
    ["ssh.allow_tcp_forwarding_disabled"]="info"
    ["ssh.allow_tcp_forwarding_enabled"]="info"
    ["ssh.client_alive_ok"]="info"
    ["ssh.client_alive_high"]="info"
    ["ssh.log_level_ok"]="info"
    ["ssh.log_level_low"]="info"
    ["ssh.max_sessions_ok"]="info"
    ["ssh.max_sessions_high"]="info"
    ["ssh.tcp_keepalive_disabled"]="info"
    ["ssh.tcp_keepalive_enabled"]="info"
    ["ssh.agent_forwarding_disabled"]="info"
    ["ssh.agent_forwarding_enabled"]="info"
    # SSH-7408 defaults-flipping options (Lynis source cross-check)
    ["ssh.ignore_rhosts_ok"]="info"
    ["ssh.ignore_rhosts_disabled"]="info"
    ["ssh.strict_modes_ok"]="info"
    ["ssh.strict_modes_disabled"]="info"
    ["ssh.permit_user_env_disabled"]="info"
    ["ssh.permit_user_env_enabled"]="info"
    ["ssh.permit_tunnel_disabled"]="info"
    ["ssh.permit_tunnel_enabled"]="info"
    ["ssh.gateway_ports_disabled"]="info"
    ["ssh.gateway_ports_enabled"]="info"

    # === UFW Module - required (core firewall) ===
    ["ufw.not_installed"]="required"
    ["ufw.enabled"]="required"
    ["ufw.disabled"]="required"
    ["ufw.firewall_active"]="required"
    ["ufw.no_firewall"]="required"
    ["ufw.firewall_empty"]="required"
    ["ufw.default_deny"]="recommended"
    ["ufw.default_accept"]="recommended"
    ["ufw.ssh_allowed"]="recommended"
    ["ufw.no_ssh_rule"]="recommended"
    ["ufw.permissive_rules"]="recommended"
    ["ufw.rules_ok"]="recommended"

    # === Fail2ban Module - recommended ===
    ["fail2ban.not_installed"]="recommended"
    # No fail2ban.installed: the module never emits that id. Absence is
    # reported as fail2ban.not_installed.
    ["fail2ban.service_active"]="recommended"
    ["fail2ban.service_inactive"]="recommended"
    ["fail2ban.service_not_enabled"]="recommended"
    ["fail2ban.ssh_jail_enabled"]="recommended"
    ["fail2ban.ssh_jail_disabled"]="recommended"
    ["fail2ban.maxretry_high"]="optional"
    ["fail2ban.custom_config"]="optional"
    ["fail2ban.default_config"]="optional"
    # Lynis TOOL-5104 cross-check
    ["fail2ban.jails_active"]="info"
    ["fail2ban.no_jails_active"]="recommended"

    # === Update Module - required ===
    ["update.apt_available"]="required"
    ["update.apt_locked"]="required"
    # Unscored on purpose: it reports that the lock state could NOT be
    # measured, and scoring a non-observation is how a host earns a free pass.
    ["update.lock_state_unknown"]="info"
    # Query failure is a non-observation: it must move no score in either
    # direction (same reasoning as lock_state_unknown above).
    ["update.check_failed"]="info"
    ["update.no_updates"]="required"
    ["update.updates_available"]="required"
    ["update.unattended_enabled"]="recommended"
    ["update.unattended_disabled"]="recommended"
    ["update.unattended_not_installed"]="recommended"

    # === Docker Module - conditional (only if Docker installed) ===
    ["docker.not_installed"]="info"
    # A runtime is there but unreachable. info, not scored: the audit did
    # not measure anything, so it must not move the score in either
    # direction — the old behaviour handed such a host a free pass.
    ["docker.daemon_unreachable"]="info"
    ["docker.exposed_ports"]="conditional"
    ["docker.no_exposed_ports"]="conditional"
    ["docker.privileged_containers"]="conditional"
    ["docker.no_privileged"]="conditional"
    ["docker.all_root_containers"]="conditional"
    ["docker.some_root_containers"]="conditional"
    ["docker.no_root_containers"]="conditional"
    ["docker.containers_with_caps"]="conditional"
    ["docker.no_extra_caps"]="conditional"
    ["docker.no_live_restore"]="info"
    ["docker.no_new_privileges_disabled"]="conditional"
    ["docker.daemon_secure"]="conditional"
    ["docker.sock_perms_loose"]="conditional"
    ["docker.sock_perms_ok"]="conditional"
    ["docker.seccomp_unconfined"]="conditional"
    ["docker.no_seccomp_unconfined"]="conditional"
    ["docker.userns_enabled"]="info"
    ["docker.userns_not_enabled"]="info"
    # CIS Docker network / secrets / resources additions
    ["docker.host_network_used"]="conditional"
    ["docker.no_host_network"]="conditional"
    ["docker.default_bridge_icc_enabled"]="conditional"
    ["docker.default_bridge_icc_disabled"]="conditional"
    ["docker.secrets_in_env"]="conditional"
    ["docker.no_env_secrets"]="conditional"
    ["docker.unlimited_memory"]="conditional"
    ["docker.memory_limits_set"]="conditional"

    # === Nginx Module - conditional (only if Nginx installed) ===
    ["nginx.not_installed"]="info"
    ["nginx.catchall_exists"]="conditional"
    ["nginx.no_catchall"]="conditional"
    # DoS hardening (CIS NGINX 5.2.1 + nginx mitigation guide)
    ["nginx.client_header_timeout_high"]="recommended"
    ["nginx.client_body_timeout_high"]="recommended"
    ["nginx.keepalive_timeout_high"]="optional"
    ["nginx.send_timeout_high"]="optional"
    ["nginx.no_rate_limiting"]="optional"
    ["nginx.reset_timedout_connection_off"]="optional"
    ["nginx.dos_hardening_ok"]="optional"

    # === Baseline Module - recommended (MAC: SELinux/AppArmor) ===
    ["baseline.apparmor_enabled"]="recommended"
    ["baseline.apparmor_disabled"]="recommended"
    ["baseline.apparmor_many_complain"]="info"
    # Disabling a profile is an operator decision, same class as leaving
    # profiles in complain mode above. Visibility is the point; scoring it
    # would move the baseline of every host that ever disabled one.
    ["baseline.apparmor_profiles_disabled"]="info"
    ["baseline.selinux_enforcing"]="recommended"
    ["baseline.selinux_permissive"]="recommended"
    ["baseline.selinux_disabled"]="recommended"
    ["baseline.selinux_many_denials"]="info"
    ["baseline.no_mac_system"]="recommended"
    ["baseline.unused_services"]="recommended"
    ["baseline.no_unused_services"]="recommended"
    ["baseline.integrity_installed"]="info"
    ["baseline.integrity_missing"]="info"
    ["baseline.insecure_services_active"]="required"
    ["baseline.insecure_services_clean"]="required"

    # === Logging Module ===
    ["logging.journald_persistent"]="recommended"
    ["logging.journald_volatile"]="recommended"
    ["logging.logrotate_ok"]="recommended"
    ["logging.logrotate_missing"]="recommended"
    ["logging.logrotate_not_configured"]="recommended"
    ["logging.auditd_configured"]="info"
    ["logging.auditd_no_rules"]="info"
    ["logging.auditd_inactive"]="info"
    ["logging.auditd_not_installed"]="info"
    ["logging.ssh_logs_ok"]="info"
    # journalctl itself failed — a non-observation, not a finding.
    ["logging.journal_unreadable"]="info"
    ["logging.ssh_many_failures"]="info"
    ["logging.ssh_some_failures"]="info"
    ["logging.sudo_logging_ok"]="recommended"
    ["logging.sudo_no_events"]="recommended"

    # === Cloudflared Module - conditional (only if installed) ===
    ["cloudflared.not_installed"]="info"
    ["cloudflared.service_active"]="conditional"
    ["cloudflared.service_inactive"]="conditional"
    ["cloudflared.tunnel_running"]="conditional"
    ["cloudflared.config_ok"]="conditional"
    ["cloudflared.config_issues"]="conditional"
    ["cloudflared.no_config"]="conditional"
    ["cloudflared.tunnels_configured"]="conditional"
    ["cloudflared.no_tunnels"]="conditional"

    # === Backup Module - optional ===
    ["backup.no_tools"]="info"
    ["backup.tools_installed"]="info"
    ["backup.no_schedule"]="info"
    ["backup.scheduled"]="info"
    ["backup.critical_paths"]="info"

    # === Networking Module - required (Lynis NETW-* cross-check) ===
    ["networking.exposed_dangerous_ports"]="required"
    ["networking.public_listeners_present"]="recommended"
    ["networking.listeners_ok"]="recommended"
    ["networking.promiscuous_interface"]="required"
    ["networking.no_promisc"]="recommended"

    # === Scheduling Module - recommended (Lynis SCHD-* cross-check) ===
    ["scheduling.at_jobs_present"]="info"
    ["scheduling.no_at_jobs"]="info"
    ["scheduling.cron_fetches_internet"]="info"
    ["scheduling.cron_clean"]="recommended"

    # === Alerts Module - optional ===
    ["alerts.configured"]="info"
    ["alerts.not_configured"]="info"
    ["alerts.no_config"]="info"
    ["alerts.capabilities_ok"]="info"
    ["alerts.no_capabilities"]="info"

    # === Kernel Module - required/recommended ===
    ["kernel.aslr_full"]="required"
    ["kernel.aslr_partial"]="required"
    ["kernel.aslr_disabled"]="required"
    ["kernel.aslr_unknown"]="required"
    ["kernel.network_params_high"]="recommended"
    ["kernel.network_params_medium"]="recommended"
    ["kernel.network_params_ok"]="recommended"
    # Zero readable sysctls — a non-observation, not a finding.
    ["kernel.network_params_unreadable"]="info"
    ["kernel.kernel_params_ok"]="recommended"
    ["kernel.kernel_params_weak"]="recommended"
    ["kernel.core_dump_ok"]="recommended"
    ["kernel.core_dump_enabled"]="recommended"
    ["kernel.unused_protocols_blocked"]="info"
    ["kernel.unused_protocols_unblocked"]="info"
    # IPv6 checks - recommended
    ["kernel.ipv6_disabled"]="info"
    ["kernel.ipv6_secure"]="recommended"
    ["kernel.ipv6_insecure"]="recommended"
    ["kernel.ipv6_unused_insecure"]="recommended"
    ["kernel.ipv6_enabled_unused"]="info"
    ["kernel.ipv6_firewall_missing"]="required"
    ["kernel.ipv6_firewall_ok"]="recommended"

    # === Filesystem Module ===
    ["filesystem.suspicious_suid"]="recommended"
    ["filesystem.suid_ok"]="recommended"
    ["filesystem.suspicious_sgid"]="optional"
    ["filesystem.sgid_ok"]="optional"
    ["filesystem.world_writable"]="recommended"
    ["filesystem.no_world_writable"]="recommended"
    ["filesystem.no_owner"]="recommended"
    ["filesystem.owner_ok"]="recommended"
    ["filesystem.sensitive_perms_wrong"]="required"
    ["filesystem.sensitive_perms_wrong_minor"]="required"
    ["filesystem.sensitive_perms_ok"]="required"
    ["filesystem.tmp_mount_ok"]="info"
    ["filesystem.tmp_not_separate"]="info"
    ["filesystem.tmp_mount_missing_opts"]="info"
    ["filesystem.umask_ok"]="info"
    ["filesystem.umask_default"]="info"
    ["filesystem.umask_weak"]="recommended"

    # === Cloud Module - info only ===
    ["cloud.provider_detected"]="info"
    ["cloud.provider_unknown"]="info"
    ["cloud.agents_found"]="info"
    ["cloud.no_known_agents"]="info"
    ["cloud.suspicious_agents"]="info"
    # IMDS posture (tier1 / tier2 cloud-only checks)
    ["cloud.imds_v1_enabled"]="required"
    ["cloud.imds_v2_only"]="info"
    ["cloud.imds_alibaba_normal_mode"]="required"
    ["cloud.imds_alibaba_hardened"]="info"
    ["cloud.user_data_leaked_secrets"]="required"
    ["cloud.user_data_clean"]="info"
    ["cloud.imds_unrestricted"]="info"
    ["cloud.imds_restricted"]="info"

    # === Users Module ===
    ["users.uid0_found"]="required"
    ["users.uid0_ok"]="required"
    ["users.empty_password"]="required"
    ["users.no_empty_password"]="required"
    ["users.nopasswd_sudo"]="required"
    ["users.system_with_shell"]="recommended"
    ["users.sudo_users"]="info"
    ["users.recent_users"]="info"
    ["users.ssh_keys_perms"]="recommended"
    ["users.ssh_keys_info"]="info"
    # Heuristic name match: shown for review, but these names are frequently
    # legitimate and a likely false positive must not lower the score.
    ["users.suspicious_names"]="info"
    ["users.unusual_home"]="recommended"
    # Operator preferences, not baseline items: pam_pwquality is not a Debian
    # default and HISTCONTROL is audit convenience, so a default-configured
    # host must not be penalised.
    ["users.pwquality_weak"]="info"
    ["users.history_insecure"]="info"
    # Lynis AUTH-* cross-check additions
    ["users.duplicate_uids"]="required"
    ["users.weak_hash_method"]="required"
    ["users.hash_rounds_low"]="info"
    ["users.faillog_disabled"]="info"
    ["users.sudoers_syntax_invalid"]="required"

    # === Timezone Module ===
    ["timezone.configured"]="info"
    ["timezone.not_configured"]="info"
    ["timezone.using_utc"]="info"
    ["timezone.ntp_synced"]="recommended"
    ["timezone.ntp_not_synced"]="recommended"
    ["timezone.ntp_disabled"]="recommended"
    ["timezone.rtc_local"]="info"
    ["timezone.locale_ok"]="info"
    ["timezone.locale_not_set"]="info"

    # === Malware Module - all required (security critical) ===
    ["malware.hidden_processes"]="required"
    ["malware.hidden_ports"]="required"
    ["malware.ld_preload"]="required"
    ["malware.ld_so_preload"]="required"
    ["malware.suspicious_lkm"]="required"
    ["malware.crypto_miner"]="required"
    ["malware.mining_pool_connection"]="required"
    ["malware.cpu_anomaly"]="info"
    ["malware.webshell"]="required"
    ["malware.deleted_binary"]="required"
    ["malware.memfd_execution"]="required"
    ["malware.suspicious_path"]="info"
    ["malware.reverse_shell"]="required"
    ["malware.c2_connection"]="info"
    ["malware.unusual_outbound"]="info"
    ["malware.clean"]="info"

    # === Webapp Module - conditional (only if webserver installed) ===
    ["webapp.nginx_server_tokens"]="conditional"
    ["webapp.nginx_server_tokens_ok"]="conditional"
    ["webapp.nginx_security_headers"]="conditional"
    ["webapp.nginx_security_headers_ok"]="conditional"
    ["webapp.nginx_hsts_missing"]="conditional"
    ["webapp.nginx_hsts_weak"]="conditional"
    ["webapp.nginx_directory_listing"]="conditional"
    ["webapp.nginx_weak_ssl"]="required"
    ["webapp.nginx_weak_ciphers"]="required"
    ["webapp.apache_server_signature"]="conditional"
    ["webapp.apache_server_tokens"]="conditional"
    ["webapp.apache_trace_enabled"]="conditional"
    ["webapp.apache_directory_index"]="conditional"
    ["webapp.apache_dangerous_modules"]="conditional"
    ["webapp.php_security_issues"]="conditional"
    ["webapp.php_dangerous_functions"]="conditional"
    ["webapp.php_session_security"]="conditional"
    ["webapp.php_open_basedir"]="conditional"
    ["webapp.ssl_cert_expiry"]="required"
    ["webapp.sensitive_files"]="required"
    ["webapp.sensitive_files_ok"]="required"
    ["webapp.backup_files"]="recommended"
    ["webapp.no_webserver"]="info"
    # Mirrors no_webserver: the web checks did not run. Reporting it is
    # honest, scoring it would penalise a host for vpssec's own gap.
    ["webapp.other_webserver"]="info"

    # === Heuristic IOC / advisory: shown, never scored. ===
    ["filesystem.suspicious_cron"]="info"
    ["filesystem.cron_ok"]="info"
    ["filesystem.non_standard_caps"]="info"
    ["filesystem.pam_umask_disabled"]="info"
    ["filesystem.caps_unavailable"]="info"
    ["kernel.container_detected"]="info"
    ["cloudflared.tunnel_list_unavailable"]="info"
    # Tool prerequisites and vpssec's own diagnostics: preflight audits vpssec,
    # not the host, and malformed_check is a vpssec bug. Never scored.
    ["_internal.malformed_check"]="info"
    # Visible in the report but scored in neither direction: the honest signal
    # is meta.complete=false and the exit code.
    ["_internal.module_failed"]="info"
    ["preflight.os_supported"]="info"
    ["preflight.os_unsupported"]="info"
    ["preflight.network_ok"]="info"
    ["preflight.network_fail"]="info"
    ["preflight.deps_ok"]="info"
    ["preflight.deps_missing"]="info"
    ["preflight.ports_ok"]="info"
    # Operator preference / non-posture
    ["ssh.no_access_control"]="info"
    ["ssh.access_control_configured"]="info"
    ["ssh.default_port"]="info"
    ["ssh.custom_port"]="info"
    ["users.password_policy_weak"]="info"
    ["users.password_policy_ok"]="info"
    ["ufw.ipv6_no_traffic"]="info"
    # Dedup — counted by the authoritative sibling check
    ["kernel.kernel_params_high"]="info"      # ASLR-off already counted by kernel.aslr_disabled
    ["update.unattended_unsupported"]="info"  # Arch passed-context state
    # Genuine posture gaps → count
    ["filesystem.dangerous_caps"]="recommended"
    ["filesystem.caps_ok"]="recommended"
    ["nginx.catchall_partial_80"]="conditional"
    ["nginx.catchall_partial_443"]="conditional"
    ["ufw.ipv6_bypass"]="recommended"
    ["ufw.ipv6_managed"]="recommended"
    ["update.reboot_required"]="recommended"
    ["update.no_reboot"]="recommended"
)

# --- Fix Safety Helper Functions ---

# Get fix safety classification. Every map read here MUST use ${MAP[$key]:-}:
# under set -u a missing key aborts the function, and a caller's 2>/dev/null
# then silently turns every non-SAFE fix into "unknown".
get_fix_safety() {
    local fix_id="$1"

    if [[ -n "${FIX_SAFE[$fix_id]:-}" ]]; then
        echo "safe"
    elif [[ -n "${FIX_CONFIRM[$fix_id]:-}" ]]; then
        echo "confirm"
    elif [[ -n "${FIX_RISKY[$fix_id]:-}" ]]; then
        echo "risky"
    elif [[ -n "${FIX_ALERT_ONLY[$fix_id]:-}" ]]; then
        echo "alert_only"
    else
        echo "unknown"
    fi
}

# Get fix warning; same ${MAP[$key]:-} discipline as get_fix_safety. A
# `fixwarn.<fix_id>` translation wins, but the English stays in the map so a
# missing key degrades to a readable warning rather than a key name.
get_fix_warning() {
    local fix_id="$1"
    local fallback=""

    if [[ -n "${FIX_CONFIRM[$fix_id]:-}" ]]; then
        fallback="${FIX_CONFIRM[$fix_id]}"
    elif [[ -n "${FIX_RISKY[$fix_id]:-}" ]]; then
        fallback="${FIX_RISKY[$fix_id]}"
    elif [[ -n "${FIX_ALERT_ONLY[$fix_id]:-}" ]]; then
        fallback="${FIX_ALERT_ONLY[$fix_id]}"
    else
        return 0
    fi

    local key="fixwarn.${fix_id}"
    local translated="${VPSSEC_I18N[$key]:-}"
    if [[ -n "$translated" ]]; then
        echo "$translated"
    else
        echo "$fallback"
    fi
}

# Check if fix can be applied (not alert-only)
can_fix() {
    local fix_id="$1"
    local safety
    safety=$(get_fix_safety "$fix_id")

    [[ "$safety" != "alert_only" && "$safety" != "unknown" ]]
}

# Check if fix requires confirmation
fix_requires_confirmation() {
    local fix_id="$1"
    local safety
    safety=$(get_fix_safety "$fix_id")

    [[ "$safety" == "confirm" || "$safety" == "risky" ]]
}

# Check if fix is risky (needs extra safeguards)
fix_is_risky() {
    local fix_id="$1"
    local safety
    safety=$(get_fix_safety "$fix_id")

    [[ "$safety" == "risky" ]]
}

# True when execute_fix itself must prompt: confirm- or risky-class AND not
# self-confirming. This is the single predicate execute_fix branches on.
fix_needs_engine_confirmation() {
    local fix_id="$1"
    fix_requires_confirmation "$fix_id" || return 1
    [[ -z "${FIX_SELF_CONFIRMED[$fix_id]:-}" ]]
}

# True when this fix cannot resolve the finding it hangs off, however well it
# runs. See FIX_TEMPLATE_ONLY. `${MAP[$key]:-}` for the same set -u reason as
# get_fix_safety.
fix_is_template_only() {
    local fix_id="$1"
    [[ -n "${FIX_TEMPLATE_ONLY[$fix_id]:-}" ]]
}

# FIX_TEMPLATE_ONLY keys as a JSON array for the reporting layer. Call once
# per document, never per check: consumers pass it as --argjson and test
# membership inside their existing jq program.
fix_template_only_ids_json() {
    printf '%s\n' "${!FIX_TEMPLATE_ONLY[@]}" | jq -Rs 'split("\n") | map(select(. != ""))'
}

# The manual step remaining after a template-only fix succeeds. Prefers a
# `fixtmpl.<fix_id>` translation, falling back to the English in the map.
get_fix_manual_step() {
    local fix_id="$1"
    local fallback="${FIX_TEMPLATE_ONLY[$fix_id]:-}"
    [[ -n "$fallback" ]] || return 0

    local translated="${VPSSEC_I18N[fixtmpl.${fix_id}]:-}"
    if [[ -n "$translated" ]]; then
        echo "$translated"
    else
        echo "$fallback"
    fi
}

# --- Score Category Helper Functions ---

# Get score category. An UNLISTED id defaults to "info", not "recommended":
# a check nobody classified must not silently drag the score down until it is
# deliberately promoted. Every emitted id is classified today; CI enforces it.
get_check_score_category() {
    local check_id="$1"
    echo "${CHECK_SCORE_CATEGORY[$check_id]:-info}"
}

# Check if a check should be included in score
# Returns: 0 = include, 1 = exclude
check_counts_in_score() {
    local check_id="$1"
    local category
    category=$(get_check_score_category "$check_id")

    case "$category" in
        required|recommended|conditional|optional)
            return 0
            ;;
        info)
            return 1
            ;;
        *)
            return 0
            ;;
    esac
}
