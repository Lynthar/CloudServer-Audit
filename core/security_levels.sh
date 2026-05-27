#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Fix safety classification and score categories
# Copyright (c) 2024

# ==============================================================================
# Fix Safety Classifications
# ==============================================================================
#
# FIX_SAFE       - Can be auto-fixed in guide mode
# FIX_CONFIRM    - Requires user confirmation before fixing
# FIX_RISKY      - High-risk, requires explicit confirmation + safeguards
# FIX_ALERT_ONLY - No auto-fix available, only alert user
#
# ==============================================================================

# Safe fixes - can be auto-applied in guide mode
declare -gA FIX_SAFE=(
    # Fail2ban - service management and config
    ["fail2ban.install"]="true"
    ["fail2ban.enable_service"]="true"
    ["fail2ban.enable_ssh_jail"]="true"
    ["fail2ban.configure_ssh_jail"]="true"

    # Update - package management
    ["update.install_unattended"]="true"
    ["update.enable_unattended"]="true"

    # Baseline - security services
    ["baseline.enable_apparmor"]="true"
    ["baseline.disable_unused"]="true"

    # Logging - logging configuration
    ["logging.enable_persistent_journal"]="true"
    ["logging.setup_logrotate"]="true"
    ["logging.install_auditd"]="true"
    ["logging.enable_auditd"]="true"
    ["logging.setup_audit_rules"]="true"

    # Kernel - sysctl hardening
    ["kernel.enable_aslr"]="true"
    ["kernel.harden_kernel"]="true"
    ["kernel.disable_core_dump"]="true"
    ["kernel.harden_ipv6"]="true"

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

    # Docker - safe daemon settings
    ["docker.enable_live_restore"]="true"

    # Template generation only
    ["docker.generate_proxy_template"]="true"
    ["cloudflared.generate_config"]="true"
    ["cloudflared.setup_service"]="true"
    ["backup.generate_templates"]="true"
    ["alerts.setup_config"]="true"
    ["alerts.generate_templates"]="true"

    # Timezone - safe configurations
    ["timezone.set_timezone"]="true"
    ["timezone.enable_ntp"]="true"
    ["timezone.sync_time"]="true"
    ["timezone.set_rtc_utc"]="true"
    ["timezone.set_locale"]="true"

    # Webapp - safe header configurations
    ["webapp.nginx_server_tokens"]="true"
    ["webapp.nginx_security_headers"]="true"
)

# Fixes requiring confirmation - medium risk
declare -gA FIX_CONFIRM=(
    # Network params may conflict with Docker/containers
    ["kernel.harden_network"]="May affect container networking if Docker/LXC is in use"

    # SELinux - can cause service issues if policies not configured
    ["baseline.selinux_set_enforcing"]="May cause service denials if SELinux policies not configured properly"

    # Requires service restart
    ["docker.enable_no_new_privileges"]="Requires Docker daemon restart"

    # Modifies web server config
    ["nginx.add_catchall"]="Modifies Nginx configuration"

    # Could affect running services
    ["ufw.set_default_deny"]="May block services not explicitly allowed"

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

    # === Review-only findings (previously emitted unclassified fix_ids that
    # resolved to "unknown"). Their dispatch handlers, where present, only
    # print guidance and return 1 — no mutation — so they belong in the
    # alert-only set: shown in the report, filtered out of the auto-fix UI. ===
    ["ssh.configure_access_control"]="Restrict access with AllowUsers/AllowGroups manually (wrong values can lock you out)"
    ["filesystem.review_caps"]="Review file capabilities; remove if not needed"
    ["ufw.review_rules"]="Review and tighten overly-permissive firewall rules manually"
    ["users.nopasswd_sudo"]="Review NOPASSWD sudoers entries manually (do not auto-modify sudoers)"
    ["users.history"]="Shell history hardening is an operator preference"
    ["users.password_policy"]="Tune password policy in /etc/login.defs manually"
    ["users.pwquality"]="Install/configure libpam-pwquality manually"
)

# ==============================================================================
# Check Score Categories
# ==============================================================================
#
# Defines how each check affects the security score:
#   required     - Always counts in score (core security)
#   recommended  - Counts if component is installed
#   conditional  - Only counts if the component is installed
#   optional     - Counts with lower weight
#   info         - Never affects score (informational only)
#
# ==============================================================================

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
    ["fail2ban.installed"]="recommended"
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
    ["update.no_updates"]="required"
    ["update.updates_available"]="required"
    ["update.unattended_enabled"]="recommended"
    ["update.unattended_disabled"]="recommended"
    ["update.unattended_not_installed"]="recommended"

    # === Docker Module - conditional (only if Docker installed) ===
    ["docker.not_installed"]="info"
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
    ["users.suspicious_names"]="recommended"
    ["users.unusual_home"]="recommended"
    # pwquality not installed / bash history protection are operator
    # preferences (pam_pwquality is not Debian-default; HISTCONTROL is
    # audit convenience), not security baseline items — explicitly
    # scored as info so a default-configured host isn't penalised.
    # These checks are emitted only on the "weak/insecure" path; there
    # is no corresponding "ok" check_id to classify.
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

    # === Score-category round: previously-unlisted check_ids, classified
    # per the hardening-posture rubric. The score measures configuration
    # posture, so heuristic IOCs, tool-prerequisite/context checks, and
    # operator-preference items are info (shown, but never move the score —
    # a false positive must not lower it). Genuine posture gaps count. ===
    # Heuristic IOC / advisory
    ["filesystem.suspicious_cron"]="info"
    ["filesystem.cron_ok"]="info"
    ["filesystem.non_standard_caps"]="info"
    ["filesystem.pam_umask_disabled"]="info"
    ["filesystem.caps_unavailable"]="info"
    ["kernel.container_detected"]="info"
    ["cloudflared.tunnel_list_unavailable"]="info"
    # Tool-prerequisite / context (preflight audits vpssec itself, not the host)
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

# ==============================================================================
# Fix Safety Helper Functions
# ==============================================================================

# Get fix safety classification.
#
# Implementation note: every map access uses `${MAP[$key]:-}` rather
# than `${MAP[$key]}`. Under `set -u` (enabled by common.sh), reading
# a missing associative-array key raises "unbound variable" and aborts
# the function; the previous version was silently masked in production
# by callers' `... 2>/dev/null || echo "unknown"` fallback, which
# meant *every non-SAFE fix* was misclassified as "unknown" — the
# whole safety badge / risky-confirmation system was bypassed
# unnoticed. The `:-` default is the canonical fix.
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

# Get fix warning message. Same `${MAP[$key]:-}` discipline as
# get_fix_safety: missing-key access under `set -u` would otherwise
# abort the function and let the caller's `2>/dev/null` swallow it.
get_fix_warning() {
    local fix_id="$1"

    if [[ -n "${FIX_CONFIRM[$fix_id]:-}" ]]; then
        echo "${FIX_CONFIRM[$fix_id]}"
    elif [[ -n "${FIX_RISKY[$fix_id]:-}" ]]; then
        echo "${FIX_RISKY[$fix_id]}"
    elif [[ -n "${FIX_ALERT_ONLY[$fix_id]:-}" ]]; then
        echo "${FIX_ALERT_ONLY[$fix_id]}"
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

# ==============================================================================
# Score Category Helper Functions
# ==============================================================================

# Get score category for a check
get_check_score_category() {
    local check_id="$1"
    echo "${CHECK_SCORE_CATEGORY[$check_id]:-recommended}"
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
