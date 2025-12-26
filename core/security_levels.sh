#!/usr/bin/env bash
# vpssec - VPS Security Check & Hardening Tool
# Security level definitions and fix safety configuration
# Copyright (c) 2024

# ==============================================================================
# Security Level Definitions
# ==============================================================================
#
# Three preset security levels:
#   basic    - Essential checks, no auto-fixes, suitable for first-time users
#   standard - Balanced security with safe auto-fixes (default)
#   strict   - Maximum security, comprehensive checks, requires confirmation
#
# ==============================================================================

# Available security levels
declare -a VPSSEC_SECURITY_LEVELS=("basic" "standard" "strict")

# Default security level
VPSSEC_DEFAULT_LEVEL="standard"

# Current security level (set at runtime)
VPSSEC_SECURITY_LEVEL="${VPSSEC_SECURITY_LEVEL:-$VPSSEC_DEFAULT_LEVEL}"

# ==============================================================================
# Fix Safety Classifications
# ==============================================================================
#
# SAFE        - Can be auto-fixed without special confirmation
# CONFIRM     - Requires user confirmation before fixing
# RISKY       - Only in strict mode, requires explicit confirmation + safeguards
# ALERT_ONLY  - No auto-fix available, only alert user
#
# ==============================================================================

# Safe fixes - can be auto-applied in standard/strict modes
declare -A FIX_SAFE=(
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

    # Kernel - sysctl hardening (except network in containers)
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
declare -A FIX_CONFIRM=(
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

# Risky fixes - strict mode only, requires safeguards
declare -A FIX_RISKY=(
    # Can lock user out of SSH
    ["ssh.disable_password_auth"]="Can lock you out if SSH key not configured properly"
    ["ssh.disable_root_login"]="Can lock you out if no admin user exists"

    # Can lock user out of server
    ["ufw.enable"]="Can lock you out if SSH not allowed"

    # Can break system packages
    ["update.apply_security"]="May break system packages or services"
)

# Alert-only - no auto-fix available
declare -A FIX_ALERT_ONLY=(
    # Require manual review and decision
    ["docker.privileged_containers"]="Container configuration requires manual review"
    ["docker.exposed_ports"]="Port exposure is an architecture decision"
    ["docker.all_root_containers"]="Container user requires Dockerfile changes"
    ["docker.some_root_containers"]="Container user requires Dockerfile changes"
    ["docker.containers_with_caps"]="Container capabilities require manual review"

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
)

# ==============================================================================
# Check Level Classification
# ==============================================================================
#
# Defines which checks are included in each security level
# Format: check_id -> minimum level (basic, standard, strict)
#
# ==============================================================================

declare -A CHECK_LEVEL=(
    # === SSH Module ===
    # Basic level - core SSH security
    ["ssh.password_auth_enabled"]="basic"
    ["ssh.password_auth_disabled"]="basic"
    ["ssh.root_login_enabled"]="basic"
    ["ssh.root_login_disabled"]="basic"
    ["ssh.pubkey_enabled"]="basic"
    ["ssh.pubkey_disabled"]="basic"
    ["ssh.admin_user_exists"]="basic"
    ["ssh.no_admin_user"]="basic"
    ["ssh.empty_password_allowed"]="basic"
    ["ssh.empty_password_denied"]="basic"

    # Standard level - additional SSH hardening
    ["ssh.admin_no_key"]="standard"
    ["ssh.authkeys_permissions"]="standard"
    ["ssh.max_auth_tries_ok"]="standard"
    ["ssh.max_auth_tries_high"]="standard"
    ["ssh.login_grace_time_ok"]="standard"
    ["ssh.login_grace_time_long"]="standard"
    ["ssh.x11_forwarding_disabled"]="standard"
    ["ssh.x11_forwarding_enabled"]="standard"
    ["ssh.weak_algorithms"]="standard"
    ["ssh.algorithms_ok"]="standard"

    # === UFW Module ===
    ["ufw.not_installed"]="basic"
    ["ufw.enabled"]="basic"
    ["ufw.disabled"]="basic"
    ["ufw.default_deny"]="standard"
    ["ufw.default_accept"]="standard"
    ["ufw.ssh_allowed"]="standard"
    ["ufw.no_ssh_rule"]="standard"

    # === Fail2ban Module ===
    ["fail2ban.not_installed"]="basic"
    ["fail2ban.installed"]="basic"
    ["fail2ban.service_active"]="standard"
    ["fail2ban.service_inactive"]="standard"
    ["fail2ban.service_not_enabled"]="standard"
    ["fail2ban.ssh_jail_enabled"]="standard"
    ["fail2ban.ssh_jail_disabled"]="standard"
    ["fail2ban.maxretry_high"]="strict"
    ["fail2ban.custom_config"]="strict"
    ["fail2ban.default_config"]="strict"

    # === Update Module ===
    ["update.apt_available"]="basic"
    ["update.apt_locked"]="basic"
    ["update.no_updates"]="basic"
    ["update.updates_available"]="basic"
    ["update.unattended_enabled"]="standard"
    ["update.unattended_disabled"]="standard"
    ["update.unattended_not_installed"]="standard"

    # === Docker Module ===
    ["docker.not_installed"]="basic"
    ["docker.exposed_ports"]="standard"
    ["docker.no_exposed_ports"]="standard"
    ["docker.privileged_containers"]="standard"
    ["docker.no_privileged"]="standard"
    ["docker.all_root_containers"]="strict"
    ["docker.some_root_containers"]="strict"
    ["docker.no_root_containers"]="strict"
    ["docker.containers_with_caps"]="strict"
    ["docker.no_extra_caps"]="strict"
    ["docker.no_live_restore"]="standard"
    ["docker.no_new_privileges_disabled"]="standard"
    ["docker.daemon_secure"]="standard"

    # === Nginx Module ===
    ["nginx.not_installed"]="basic"
    ["nginx.catchall_exists"]="standard"
    ["nginx.no_catchall"]="standard"

    # === Baseline Module (MAC: SELinux/AppArmor) ===
    ["baseline.apparmor_enabled"]="standard"
    ["baseline.apparmor_disabled"]="standard"
    ["baseline.apparmor_many_complain"]="strict"
    ["baseline.selinux_enforcing"]="standard"
    ["baseline.selinux_permissive"]="standard"
    ["baseline.selinux_disabled"]="standard"
    ["baseline.selinux_many_denials"]="strict"
    ["baseline.no_mac_system"]="standard"
    ["baseline.unused_services"]="standard"
    ["baseline.no_unused_services"]="standard"

    # === Logging Module ===
    ["logging.journald_persistent"]="basic"
    ["logging.journald_volatile"]="basic"
    ["logging.logrotate_ok"]="standard"
    ["logging.logrotate_missing"]="standard"
    ["logging.logrotate_not_configured"]="standard"
    ["logging.auditd_configured"]="strict"
    ["logging.auditd_no_rules"]="strict"
    ["logging.auditd_inactive"]="strict"
    ["logging.auditd_not_installed"]="strict"
    ["logging.ssh_logs_ok"]="basic"
    ["logging.ssh_many_failures"]="basic"
    ["logging.ssh_some_failures"]="basic"
    ["logging.sudo_logging_ok"]="standard"
    ["logging.sudo_no_events"]="standard"

    # === Cloudflared Module ===
    ["cloudflared.not_installed"]="basic"
    ["cloudflared.service_active"]="standard"
    ["cloudflared.service_inactive"]="standard"
    ["cloudflared.tunnel_running"]="standard"
    ["cloudflared.config_ok"]="standard"
    ["cloudflared.config_issues"]="standard"
    ["cloudflared.no_config"]="standard"
    ["cloudflared.tunnels_configured"]="standard"
    ["cloudflared.no_tunnels"]="standard"

    # === Backup Module ===
    ["backup.no_tools"]="standard"
    ["backup.tools_installed"]="standard"
    ["backup.no_schedule"]="standard"
    ["backup.scheduled"]="standard"
    ["backup.critical_paths"]="standard"

    # === Alerts Module ===
    ["alerts.configured"]="strict"
    ["alerts.not_configured"]="strict"
    ["alerts.no_config"]="strict"
    ["alerts.capabilities_ok"]="strict"
    ["alerts.no_capabilities"]="strict"

    # === Kernel Module ===
    ["kernel.aslr_full"]="basic"
    ["kernel.aslr_partial"]="basic"
    ["kernel.aslr_disabled"]="basic"
    ["kernel.aslr_unknown"]="basic"
    ["kernel.network_params_high"]="standard"
    ["kernel.network_params_medium"]="standard"
    ["kernel.network_params_ok"]="standard"
    ["kernel.kernel_params_ok"]="standard"
    ["kernel.kernel_params_weak"]="standard"
    ["kernel.core_dump_ok"]="standard"
    ["kernel.core_dump_enabled"]="standard"
    # IPv6 checks
    ["kernel.ipv6_disabled"]="standard"
    ["kernel.ipv6_secure"]="standard"
    ["kernel.ipv6_insecure"]="standard"
    ["kernel.ipv6_unused_insecure"]="standard"
    ["kernel.ipv6_enabled_unused"]="standard"
    ["kernel.ipv6_firewall_missing"]="standard"
    ["kernel.ipv6_firewall_ok"]="standard"

    # === Filesystem Module ===
    ["filesystem.suspicious_suid"]="standard"
    ["filesystem.suid_ok"]="standard"
    ["filesystem.suspicious_sgid"]="strict"
    ["filesystem.sgid_ok"]="strict"
    ["filesystem.world_writable"]="standard"
    ["filesystem.no_world_writable"]="standard"
    ["filesystem.no_owner"]="standard"
    ["filesystem.owner_ok"]="standard"
    ["filesystem.sensitive_perms_wrong"]="basic"
    ["filesystem.sensitive_perms_ok"]="basic"
    ["filesystem.tmp_mount_ok"]="strict"
    ["filesystem.tmp_not_separate"]="strict"
    ["filesystem.tmp_mount_missing_opts"]="strict"
    ["filesystem.umask_ok"]="standard"
    ["filesystem.umask_default"]="standard"
    ["filesystem.umask_weak"]="standard"

    # === Cloud Module ===
    ["cloud.provider_detected"]="basic"
    ["cloud.provider_unknown"]="basic"
    ["cloud.agents_found"]="standard"
    ["cloud.no_known_agents"]="standard"
    ["cloud.suspicious_agents"]="strict"

    # === Users Module ===
    ["users.uid0_found"]="basic"
    ["users.uid0_ok"]="basic"
    ["users.empty_password"]="basic"
    ["users.no_empty_password"]="basic"
    ["users.nopasswd_sudo"]="basic"
    ["users.system_with_shell"]="standard"
    ["users.sudo_users"]="standard"
    ["users.recent_users"]="standard"
    ["users.ssh_keys_perms"]="standard"
    ["users.ssh_keys_info"]="standard"
    ["users.suspicious_names"]="strict"
    ["users.unusual_home"]="strict"

    # === Timezone Module ===
    ["timezone.configured"]="basic"
    ["timezone.not_configured"]="basic"
    ["timezone.using_utc"]="basic"
    ["timezone.ntp_synced"]="basic"
    ["timezone.ntp_not_synced"]="basic"
    ["timezone.ntp_disabled"]="basic"
    ["timezone.time_accurate"]="basic"
    ["timezone.time_drift"]="basic"
    ["timezone.rtc_local"]="standard"
    ["timezone.locale_ok"]="basic"
    ["timezone.locale_not_set"]="basic"

    # === Malware Module ===
    # Rootkit detection - strict mode only (can have false positives)
    ["malware.hidden_processes"]="strict"
    ["malware.hidden_ports"]="strict"
    ["malware.ld_preload"]="strict"
    ["malware.ld_so_preload"]="strict"
    ["malware.suspicious_lkm"]="strict"
    # Crypto miner detection - standard mode
    ["malware.crypto_miner"]="standard"
    ["malware.mining_pool_connection"]="standard"
    ["malware.cpu_anomaly"]="standard"
    # WebShell detection - standard mode
    ["malware.webshell"]="standard"
    # Suspicious process detection - standard mode
    ["malware.deleted_binary"]="standard"
    ["malware.memfd_execution"]="standard"
    ["malware.suspicious_path"]="standard"
    # Network anomaly detection - standard mode
    ["malware.reverse_shell"]="standard"
    ["malware.c2_connection"]="standard"
    ["malware.unusual_outbound"]="standard"
    # Clean status
    ["malware.clean"]="basic"

    # === Webapp Module ===
    # Nginx checks
    ["webapp.nginx_server_tokens"]="standard"
    ["webapp.nginx_server_tokens_ok"]="standard"
    ["webapp.nginx_security_headers"]="standard"
    ["webapp.nginx_security_headers_ok"]="standard"
    ["webapp.nginx_hsts_missing"]="standard"
    ["webapp.nginx_directory_listing"]="standard"
    ["webapp.nginx_weak_ssl"]="basic"
    ["webapp.nginx_weak_ciphers"]="basic"
    # Apache checks
    ["webapp.apache_server_signature"]="standard"
    ["webapp.apache_server_tokens"]="standard"
    ["webapp.apache_trace_enabled"]="standard"
    ["webapp.apache_directory_index"]="standard"
    ["webapp.apache_dangerous_modules"]="standard"
    # PHP checks
    ["webapp.php_security_issues"]="standard"
    ["webapp.php_dangerous_functions"]="standard"
    ["webapp.php_session_security"]="standard"
    ["webapp.php_open_basedir"]="standard"
    # SSL/TLS checks
    ["webapp.ssl_cert_expiry"]="basic"
    # Exposure checks
    ["webapp.sensitive_files"]="standard"
    ["webapp.sensitive_files_ok"]="standard"
    ["webapp.backup_files"]="standard"
    # Status checks
    ["webapp.no_webserver"]="basic"
)

# ==============================================================================
# Check Score Categories
# ==============================================================================
#
# Defines how each check affects the security score:
#   required     - Always counts in score (core security)
#   recommended  - Counts if component is installed, deduct for missing config
#   conditional  - Only counts if the component is installed
#   optional     - Only counts in strict mode
#   info         - Never affects score (informational only)
#
# ==============================================================================

declare -A CHECK_SCORE_CATEGORY=(
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
    ["ssh.max_auth_tries_ok"]="recommended"
    ["ssh.max_auth_tries_high"]="recommended"
    ["ssh.login_grace_time_ok"]="recommended"
    ["ssh.login_grace_time_long"]="recommended"
    ["ssh.x11_forwarding_disabled"]="recommended"
    ["ssh.x11_forwarding_enabled"]="recommended"
    ["ssh.weak_algorithms"]="optional"
    ["ssh.algorithms_ok"]="optional"

    # === UFW Module - required (core firewall) ===
    ["ufw.not_installed"]="required"
    ["ufw.enabled"]="required"
    ["ufw.disabled"]="required"
    ["ufw.default_deny"]="recommended"
    ["ufw.default_accept"]="recommended"
    ["ufw.ssh_allowed"]="recommended"
    ["ufw.no_ssh_rule"]="recommended"

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
    ["docker.no_live_restore"]="conditional"
    ["docker.no_new_privileges_disabled"]="conditional"
    ["docker.daemon_secure"]="conditional"

    # === Nginx Module - conditional (only if Nginx installed) ===
    ["nginx.not_installed"]="info"
    ["nginx.catchall_exists"]="conditional"
    ["nginx.no_catchall"]="conditional"

    # === Baseline Module - recommended (MAC: SELinux/AppArmor) ===
    ["baseline.apparmor_enabled"]="recommended"
    ["baseline.apparmor_disabled"]="recommended"
    ["baseline.apparmor_many_complain"]="recommended"
    ["baseline.selinux_enforcing"]="recommended"
    ["baseline.selinux_permissive"]="recommended"
    ["baseline.selinux_disabled"]="recommended"
    ["baseline.selinux_many_denials"]="info"
    ["baseline.no_mac_system"]="recommended"
    ["baseline.unused_services"]="recommended"
    ["baseline.no_unused_services"]="recommended"

    # === Logging Module ===
    ["logging.journald_persistent"]="recommended"
    ["logging.journald_volatile"]="recommended"
    ["logging.logrotate_ok"]="recommended"
    ["logging.logrotate_missing"]="recommended"
    ["logging.logrotate_not_configured"]="recommended"
    ["logging.auditd_configured"]="optional"
    ["logging.auditd_no_rules"]="optional"
    ["logging.auditd_inactive"]="optional"
    ["logging.auditd_not_installed"]="optional"
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
    ["backup.no_tools"]="optional"
    ["backup.tools_installed"]="optional"
    ["backup.no_schedule"]="optional"
    ["backup.scheduled"]="optional"
    ["backup.critical_paths"]="optional"

    # === Alerts Module - optional ===
    ["alerts.configured"]="optional"
    ["alerts.not_configured"]="optional"
    ["alerts.no_config"]="optional"
    ["alerts.capabilities_ok"]="optional"
    ["alerts.no_capabilities"]="optional"

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
    ["filesystem.sensitive_perms_ok"]="required"
    ["filesystem.tmp_mount_ok"]="optional"
    ["filesystem.tmp_not_separate"]="optional"
    ["filesystem.tmp_mount_missing_opts"]="optional"
    ["filesystem.umask_ok"]="recommended"
    ["filesystem.umask_default"]="recommended"
    ["filesystem.umask_weak"]="recommended"

    # === Cloud Module - info only ===
    ["cloud.provider_detected"]="info"
    ["cloud.provider_unknown"]="info"
    ["cloud.agents_found"]="info"
    ["cloud.no_known_agents"]="info"
    ["cloud.suspicious_agents"]="info"

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

    # === Timezone Module ===
    ["timezone.configured"]="info"
    ["timezone.not_configured"]="recommended"
    ["timezone.using_utc"]="info"
    ["timezone.ntp_synced"]="recommended"
    ["timezone.ntp_not_synced"]="recommended"
    ["timezone.ntp_disabled"]="recommended"
    ["timezone.time_accurate"]="recommended"
    ["timezone.time_drift"]="recommended"
    ["timezone.rtc_local"]="recommended"
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
    ["malware.cpu_anomaly"]="recommended"
    ["malware.webshell"]="required"
    ["malware.deleted_binary"]="required"
    ["malware.memfd_execution"]="required"
    ["malware.suspicious_path"]="recommended"
    ["malware.reverse_shell"]="required"
    ["malware.c2_connection"]="required"
    ["malware.unusual_outbound"]="recommended"
    ["malware.clean"]="info"

    # === Webapp Module - conditional (only if webserver installed) ===
    ["webapp.nginx_server_tokens"]="conditional"
    ["webapp.nginx_server_tokens_ok"]="conditional"
    ["webapp.nginx_security_headers"]="conditional"
    ["webapp.nginx_security_headers_ok"]="conditional"
    ["webapp.nginx_hsts_missing"]="conditional"
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
)

# ==============================================================================
# Security Level Helper Functions
# ==============================================================================

# Check if a security level is valid
_level_is_valid() {
    local level="$1"
    for l in "${VPSSEC_SECURITY_LEVELS[@]}"; do
        [[ "$l" == "$level" ]] && return 0
    done
    return 1
}

# Get numeric value for security level (for comparison)
_level_to_num() {
    local level="$1"
    case "$level" in
        basic)    echo 1 ;;
        standard) echo 2 ;;
        strict)   echo 3 ;;
        *)        echo 0 ;;
    esac
}

# Check if current level includes a check
level_includes_check() {
    local check_id="$1"
    local check_level="${CHECK_LEVEL[$check_id]:-basic}"

    local current_num=$(_level_to_num "$VPSSEC_SECURITY_LEVEL")
    local check_num=$(_level_to_num "$check_level")

    [[ $current_num -ge $check_num ]]
}

# Get fix safety classification
get_fix_safety() {
    local fix_id="$1"

    if [[ -n "${FIX_SAFE[$fix_id]}" ]]; then
        echo "safe"
    elif [[ -n "${FIX_CONFIRM[$fix_id]}" ]]; then
        echo "confirm"
    elif [[ -n "${FIX_RISKY[$fix_id]}" ]]; then
        echo "risky"
    elif [[ -n "${FIX_ALERT_ONLY[$fix_id]}" ]]; then
        echo "alert_only"
    else
        echo "unknown"
    fi
}

# Get fix warning message
get_fix_warning() {
    local fix_id="$1"

    if [[ -n "${FIX_CONFIRM[$fix_id]}" ]]; then
        echo "${FIX_CONFIRM[$fix_id]}"
    elif [[ -n "${FIX_RISKY[$fix_id]}" ]]; then
        echo "${FIX_RISKY[$fix_id]}"
    elif [[ -n "${FIX_ALERT_ONLY[$fix_id]}" ]]; then
        echo "${FIX_ALERT_ONLY[$fix_id]}"
    fi
}

# Check if fix can be auto-applied at current level
can_auto_fix() {
    local fix_id="$1"
    local safety=$(get_fix_safety "$fix_id")

    case "$safety" in
        safe)
            # Safe fixes allowed in standard and strict modes
            [[ "$VPSSEC_SECURITY_LEVEL" != "basic" ]]
            ;;
        confirm)
            # Confirm fixes allowed in standard (with confirm) and strict modes
            [[ "$VPSSEC_SECURITY_LEVEL" != "basic" ]]
            ;;
        risky)
            # Risky fixes only allowed in strict mode
            [[ "$VPSSEC_SECURITY_LEVEL" == "strict" ]]
            ;;
        alert_only|unknown)
            # Never auto-fix
            return 1
            ;;
    esac
}

# Check if fix requires confirmation
fix_requires_confirmation() {
    local fix_id="$1"
    local safety=$(get_fix_safety "$fix_id")

    case "$safety" in
        safe)
            return 1  # No confirmation needed
            ;;
        confirm)
            # In standard mode, always confirm
            # In strict mode, only confirm first time
            [[ "$VPSSEC_SECURITY_LEVEL" != "strict" ]]
            ;;
        risky)
            return 0  # Always confirm risky fixes
            ;;
        *)
            return 0  # Unknown, require confirmation
            ;;
    esac
}

# Set security level
set_security_level() {
    local level="$1"

    if _level_is_valid "$level"; then
        VPSSEC_SECURITY_LEVEL="$level"
        export VPSSEC_SECURITY_LEVEL
        return 0
    else
        log_error "Invalid security level: $level"
        return 1
    fi
}

# Get current security level
get_security_level() {
    echo "$VPSSEC_SECURITY_LEVEL"
}

# Print security level description
# Takes optional second arg for mode (audit/guide)
print_security_level_info() {
    local level="$1"
    local mode="${2:-${VPSSEC_MODE:-audit}}"

    if [[ "$mode" == "guide" ]]; then
        # Guide mode - describe fix behavior
        case "$level" in
            basic)
                echo "Basic - Essential security checks, no automatic fixes"
                echo "  • Core SSH, firewall, and update checks"
                echo "  • Alert-only mode for all issues"
                echo "  • Suitable for first-time users"
                ;;
            standard)
                echo "Standard - Balanced security with safe auto-fixes (recommended)"
                echo "  • Comprehensive security checks"
                echo "  • Auto-fix for low-risk items"
                echo "  • Confirmation required for medium-risk changes"
                ;;
            strict)
                echo "Strict - Maximum security for production servers"
                echo "  • All available security checks"
                echo "  • More aggressive auto-fixes"
                echo "  • Includes risky fixes with safeguards"
                ;;
        esac
    else
        # Audit mode - describe check scope
        case "$level" in
            basic)
                echo "Basic - Core security checks only"
                echo "  • SSH authentication & root login"
                echo "  • Firewall status"
                echo "  • System updates"
                echo "  • Critical file permissions"
                ;;
            standard)
                echo "Standard - Comprehensive security audit (recommended)"
                echo "  • All basic checks plus:"
                echo "  • Service hardening (fail2ban, AppArmor)"
                echo "  • Docker security (if installed)"
                echo "  • Kernel parameters"
                echo "  • Filesystem security"
                ;;
            strict)
                echo "Strict - Full compliance audit"
                echo "  • All standard checks plus:"
                echo "  • Audit logging (auditd)"
                echo "  • Alert configuration"
                echo "  • SGID binaries"
                echo "  • /tmp mount options"
                ;;
        esac
    fi
}

# Count checks at each level
count_checks_by_level() {
    local level="$1"
    local count=0

    for check_id in "${!CHECK_LEVEL[@]}"; do
        local check_level="${CHECK_LEVEL[$check_id]}"
        case "$level" in
            basic)
                [[ "$check_level" == "basic" ]] && ((count++))
                ;;
            standard)
                [[ "$check_level" == "basic" || "$check_level" == "standard" ]] && ((count++))
                ;;
            strict)
                ((count++))  # All checks
                ;;
        esac
    done

    echo "$count"
}

# Get score category for a check
get_check_score_category() {
    local check_id="$1"
    echo "${CHECK_SCORE_CATEGORY[$check_id]:-required}"
}

# Check if a check should be included in score
# Returns: 0 = include, 1 = exclude
check_counts_in_score() {
    local check_id="$1"
    local category
    category=$(get_check_score_category "$check_id")

    case "$category" in
        required|recommended)
            # Always count
            return 0
            ;;
        conditional)
            # Only count if parent component is installed
            # This is determined by checking if we have any non-"not_installed" checks
            # for the same module. The caller should handle this.
            return 0
            ;;
        optional)
            # Only count in strict mode
            [[ "$VPSSEC_SECURITY_LEVEL" == "strict" ]]
            ;;
        info)
            # Never count
            return 1
            ;;
        *)
            # Unknown category, include by default
            return 0
            ;;
    esac
}
