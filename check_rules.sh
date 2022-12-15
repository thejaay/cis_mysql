#!/bin/bash

MYSQL_SERVICE="mariadb"
MYSQL_BIN="mysql"
# Consider using command line argument for username/password
MYSQL_OPTS="--skip-column-names --silent --raw"
# /!\ WARNING /!\ Remediation will apply the changes even if rule is already correct. Current values will be overwritten by default expected values
REMEDIATE="NO"
#REMEDIATE="YES"

MYSQL_CONFIG_FILE="/etc/my.cnf"
MYSQL_USER="mysql"
MYSQL_DATADIR="/var/lib/mysql/"

ERR_COLOR='\033[0;31m'
OK_COLOR='\033[0;32m'
INFO_COLOR='\033[0;36m'
WARN_COLOR='\033[0;33m'
NC='\033[0m' # No Color

err_count=0

# Wrapper for SQL query
mysql_call()
{
 ${MYSQL_BIN} ${MYSQL_OPTS} -e "${1}"
}

# Format error message
print_err()
{
	err_count=$((${err_count} + 1))
  echo -e "      ${ERR_COLOR} ${1} ${NC}"
}

# Format success message
print_ok()
{
  echo -e "      ${OK_COLOR} ${1} ${NC}"
}

# Format warning message
print_warn()
{
  echo -e "      ${WARN_COLOR} ${1} ${NC}"
}

# Format info message
print_info()
{
  echo -e "      ${INFO_COLOR} ${1} ${NC}"
}

# Check service is running
systemctl status ${MYSQL_SERVICE} 2>&1> /dev/null
if [ $? -ne 0 ]
then
	print_err "${MYSQL_SERVICE} service not running"
	exit
fi

echo "1 Operating System Level Configuration"
echo "  1.1 Place Databases on Non-System Partitions (Manual)"
print_warn "Manual test"
# ---------------------------------------------------------------------------------------------------
echo "  1.2 Use Dedicated Least Privileged Account for MySQL Daemon/Service (Automated)"
ret=$(ps -ef | egrep "^${MYSQL_USER}.*$")
if [ "x${ret}" = "x" ]
then
    print_err "No dedicated user found in process list"
else
    print_ok "'${MYSQL_USER}' user found in process list"
    print_info "Please make sure the ${MYSQL_USER} user is running the sql daemon/service with \"ps -ef | egrep '^${MYSQL_USER}.*$'\" "
fi
print_info "Make sure the sql daemon/service is running before this test"
# ---------------------------------------------------------------------------------------------------
echo "  1.3 Disable MySQL Command History (Automated)"
ret=$(find /{home,root} -name ".mysql_history" 2> /dev/null)
if [ "x${ret}" = "x" ]
then
    print_ok "OK"
else
	for d in ${ret}
	do
		name=$(realpath ${d})
		if [ "x${name}" = "x/dev/null" ]
		then
			print_ok "${d} point to /dev/null"
			continue
		fi
    		print_err "MySQL history present : ${d}"
		if [ "x${REMEDIATE}" = "xYES" ]
		then
			rm ${d}
			ln -s /dev/null ${d}
		fi
	done
fi
# ---------------------------------------------------------------------------------------------------
echo "  1.4 Verify That the MYSQL_PWD Environment Variable is Not in Use (Automated)"
ret=$(grep MYSQL_PWD /proc/*/environ 2> /dev/null)
if [ "x${ret}" = "x" ]
then
    print_ok "OK"
else
    print_err "Error"
fi
# ---------------------------------------------------------------------------------------------------
echo "  1.5 Ensure Interactive Login is Disabled (Automated)"
ret=$(getent passwd mysql | egrep "(\/bin\/false|\/sbin\/nologin)$")
if [ "x${ret}" = "x" ]
then
    print_err "mysql user login is not disabled"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		usermod -s /bin/false mysql
		# Also OK
		# usermod -s /bin/nologin mysql
	fi
else
    print_ok "${MYSQL_USER} shell is set to ${ret}"
fi
# ---------------------------------------------------------------------------------------------------
echo "  1.6 Verify That 'MYSQL_PWD' is Not Set in Users' Profiles (Automated)"
ret=$(grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile} 2> /dev/null)
if [ ! "x${ret}" = "x" ]
then
    print_err "MYSQL_PWD present in at least one profile"
else
    print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  1.7 Ensure MySQL is Run Under a Sandbox Environment (Manual)"
print_warn "Manual test"
# ---------------------------------------------------------------------------------------------------
echo "2  Installation and Planning"
echo "  2.1 Backup and Disaster Recovery"
echo "    2.1.1 Backup Policy in Place (Manual)"
print_warn "Manual test"
echo "    2.1.2 Verify Backups are Good (Manual)"
print_warn "Manual test"
echo "    2.1.3 Secure Backup Credentials (Manual)"
print_warn "Manual test"
echo "    2.1.4 The Backups Should be Properly Secured (Manual)"
print_warn "Manual test"
# ---------------------------------------------------------------------------------------------------
echo "    2.1.5 Point-in-Time Recovery (Automated)"
ret=$(mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - Log Expiration' as Note FROM information_schema.global_variables where variable_name = 'binlog_expire_logs_seconds';")
if [ "x${ret}" = "x" ] || [ "x${ret}" = "x0" ]
then
	print_err "'binlog_expire_logs_seconds' is not configured (feature startin with MariaDB 10.6.1)"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		print_warn "Remediation : TODO if MariaDB >= 10.6.1"
		# 30 days
		# MariaDB >= 10.6.1
		#echo 'binlog_expire_logs_seconds=259200' >> ${MYSQL_CONFIG_FILE}
	fi
else
    print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "    2.1.6 Disaster Recovery (DR) Plan (Manual)"
print_warn "Manual test"
echo "    2.1.7 Backup of Configuration and Related Files (Manual)"
print_warn "Manual test"
# ---------------------------------------------------------------------------------------------------
echo "  2.2 Data Encryption"
echo "    2.2.1  Ensure Binary and Relay Logs are Encrypted (Automated)"
# MariaDB
ret=$(mysql_call "SELECT VARIABLE_VALUE FROM information_schema.global_variables where variable_name = 'encrypt_binlog';")
# MySQL
#ret=$(mysql_call "SELECT VARIABLE_VALUE FROM information_schema.global_variables where variable_name = 'binlog_encryption';")
if [ ! "x${ret}" = "xON" ]
then
    print_err "'binlog_encryption' is not configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		# MariaDB
		echo 'encrypt_binlog=ON' >> ${MYSQL_CONFIG_FILE}
		# MySQL
		#mysql_call "SET GLOBAL binlog_encryption=ON;"
	fi
else
    print_ok "binlog_encryption is ON"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.3 Dedicate the Machine Running MySQL (Manual)"
print_warn "Manual test"
echo "  2.4 Do Not Specify Passwords in the Command Line (Manual)"
print_warn "Manual test"
echo "  2.5 Do Not Reuse Usernames (Manual)"
print_warn "Manual test"
echo "  2.6 Ensure Non-Default, Unique Cryptographic Material is in Use (Manual)"
print_warn "Manual test"
# ---------------------------------------------------------------------------------------------------
echo "  2.7 Ensure 'password_lifetime' is Less Than or Equal to '365 ' (Automated)"
ret=$(mysql_call "SELECT VARIABLE_VALUE FROM information_schema.global_variables where VARIABLE_NAME like 'default_password_lifetime';")
if [ ! "x${ret}" = "x365" ]
then
	print_err "password_lifetime is different than 365 (found ${ret})"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		# MariaDB
		echo "default_password_lifetime=365" >> ${MYSQL_CONFIG_FILE}
		# MySQL
		#mysql_call "set persist default_password_lifetime = 365;"
	fi
else
    print_ok "Password lifetime set to ${ret}"
fi
# # Not available in MariaDB
#print_info "When the global password lifetime is less than or equal to 365, or not configured, each user account shall be checked by executing the following command:"
#mysql_call "SELECT user, host, password_lifetime from mysql.user where password_lifetime = 0 OR password_lifetime >= 365;"
#if [ "x${REMEDIATE}" = "xYES" ]
#then
#	print_info "Manually run \"ALTER USER '<username>'@'<localhost>' PASSWORD EXPIRE INTERVAL 365 DAY;\" for each faulty users"
#fi
# ---------------------------------------------------------------------------------------------------
echo "  2.8 Ensure Password Resets Require Strong Passwords (Automated)"
ret=$(mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables where VARIABLE_NAME in ('password_history', 'password_reuse_interval');")
if [ "x${ret}" = "x" ]
then
	print_err "'password_reuse_check' plugin is not installed (starting with MariaDB 10.7)"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		print_warn "Remediation : TODO if MariaDB >= 10.7"
		# MariaDB >= 10.7
		#echo "plugin_load_add=password_reuse_check" >> ${MYSQL_CONFIG_FILE}
		# MySQL
		#mysql_call "SET PERSIST password_history = 5;"
		#mysql_call "SET PERSIST password_reuse_interval = 365;"
	fi
fi

# ---------------------------------------------------------------------------------------------------
echo "  2.9 Require Current Password for Password Reset (Automated)"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables where VARIABLE_NAME in ('password_require_current');"
if [ "x${REMEDIATE}" = "xYES" ]
then
	mysql_call "SET PERSIST password_require_current=ON;"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.10 Use Dual Passwords to Enable Higher Frequency Password Rotation (Manual)"
print_warn "Manual test"
echo "  2.11 Lock Out Accounts if Not Currently in Use (Manual)"
print_warn "Manual test"
# ---------------------------------------------------------------------------------------------------
echo "  2.12 Ensure AES Encryption Mode for AES_ENCRYPT/AES_DECRYPT is Configured Correctly (Automated)"
print_info "'block_encryption_mode' is not present for MariaDB"
#mysql_call "select @@block_encryption_mode;"
#if [ "x${REMEDIATE}" = "xYES" ]
#then
#    echo "block_encryption_mode=aes-256-cbc" >> ${MYSQL_CONFIG_FILE}
#	# Also OK
#	# mysql_call "set persist block_encryption_mode='aes-256-cbc'"
#fi
# ---------------------------------------------------------------------------------------------------
echo "  2.13 Ensure Socket Peer-Credential Authentication is Used Appropriately (Manual)"
print_warn "Manual test"
# ---------------------------------------------------------------------------------------------------
echo "  2.14 Ensure MySQL is Bound to an IP Address (Automated)"
ret=$(mysql_call "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'bind_address';")
if [ "x${ret}" = "x" ]
then
    print_err "No binding adress found"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
    		print_warn "Run following command echo \"bind_address=X.X.X.X\" >> ${MYSQL_CONFIG_FILE}"
	fi
else
    print_ok "Server is binding to '${ret}'"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.15 Limit Accepted Transport Layer Security (TLS) Versions (Automated)"
ret=$(mysql_call "select @@tls_version where @@tls_version like '%TLSv1,%' or @@tls_version like '%TLSv1' or @@tls_version like '%TLSv1.1%';")
if [ ! "x${ret}" = "x" ]
then
    print_err "TLS version contains v1 and/or v1.1"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
    		echo "tls_version=TLSv1.2,TLSv1.3" >> ${MYSQL_CONFIG_FILE}
	fi
else
    print_ok "TLS version configured correctly"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.16 Require Client-Side Certificates (X.509) (Automated)"
ret=$(mysql_call "select user, host, ssl_type from mysql.user where user not in ('mysql.infoschema', 'mysql.session', 'mysql.sys') AND ssl_type NOT IN ('X509', 'SSL');")
if [ ! "x${ret}" = "x" ]
then
    print_err "Certificate is not enabled for at least one client"
else
    print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.17 Ensure Only Approved Ciphers are Used (Automated)"
ret=$(mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME IN ('ssl_cipher') AND VARIABLE_VALUE = 'ECDHE-ECDSA-AES128-GCM-SHA256';")
if [ "x${ret}" = "x" ]
then
    print_err "SSL_CIPHER error"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "ssl_cipher='ECDHE-ECDSA-AES128-GCM-SHA256'" >> ${MYSQL_CONFIG_FILE}
	fi
else
    print_ok "ssl_cipher set to ${ret}"
fi
ret=$(mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME IN ('tls_ciphersuites') AND VARIABLE_VALUE = 'TLS_AES_256_GCM_SHA384';")
if [ "x${ret}" = "x" ]
then
    print_err "TLS_CIPHERSUITE error"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		print_warn "'tls_ciphersuites' not present in MariaDB"
		#echo "tls_ciphersuites='TLS_AES_256_GCM_SHA384'" >> ${MYSQL_CONFIG_FILE}
	fi
else
    print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.18 Implement Connection Delays to Limit Failed Login Attempts (Automated)"
print_info "'connection_control' plugin not present in MariaDB"
#ret=$(mysql_call "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE 'connection%';")
#if [ "x${ret}" = "x" ]
#then
#    print_err "No connection plugin found"
#fi
#print_info "Following plugins must be presents :"
#print_info "CONNECTION_CONTROL | ACTIVE"
#print_info "CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS | ACTIVE"
#mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME LIKE 'connection_control%';"
#print_info "If connection_control_failed_connections_threshold is less than 5 (attempts), this is a fail."
#print_info "If connection_control_min_connection_delay is less than 60000 (ms - 1 minute), this is a fail."
#print_info "Max delay connection_control_max_connection_delay is 0 or less than 1920000 (ms, 32 minutes) a, this is a fail."
#mysql_call "select host, user, JSON_EXTRACT(user_attributes, '$.Password_locking.failed_login_attempts') as failed_login_attempts from mysql.user;"
#print_info "If failed login attempts is less than 12 this is a fail."
# ---------------------------------------------------------------------------------------------------
echo "3 File Permissions"
# ---------------------------------------------------------------------------------------------------
echo "  3.1 Ensure 'datadir' Has Appropriate Permissions (Automated)"
dir=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'datadir';")
ret=$(sudo ls -ld ${dir} | grep "drwxr-x---.*mysql.*mysql")
if [ "x${ret}" = "x" ]
then
	print_err "'${dir}' is not correctly configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		chmod 750 ${dir}
		chown ${MYSQL_USER}:${MYSQL_USER} ${dir}
	fi
else
    print_ok "'${dir}' permissions OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.2 Ensure 'log_bin_basename' Files Have Appropriate Permissions (Automated)"
log=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'log_bin_basename';")
if [ "x${log}" = "x" ]
then
  print_err "'log_bin_basename' not configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		sleep 0
		#mysql_call "SET sql_log_bin = 1;"
		#echo "log_bin='ON'" >> ${MYSQL_CONFIG_FILE}
		#echo "log_bin_basename='${MYSQL_DATADIR}/binlog'" >> ${MYSQL_CONFIG_FILE}
	fi
  
else
	ret=$(ls -l | egrep "^-(?![r|w]{2}-[r|w]{2}----.*${MYSQL_USER}\s*${MYSQL_USER}).*${log}.*$")
	if [ "x${ret}" = "x" ]
	then
	    print_ok "'${log}' permissions OK"
	else
  		print_err "'${log}' permissions Error"
		if [ "x${REMEDIATE}" = "xYES" ]
		then
			chmod 600 ${log}
			chown ${MYSQL_USER}:${MYSQL_USER} ${log}
		fi
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.3 Ensure 'log_error' Has Appropriate Permissions (Automated)"
log=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'log_error';")
ret=$(ls -l ${log} | grep "^-rw-------.*${MYSQL_USER}.*${MYSQL_USER}.*$")
if [ "x${ret}" = "x" ]
then
    print_err "'${log}' permissions Error"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		chmod 660 ${log} 
		chown ${MYSQL_USER}:${MYSQL_USER} ${log}
	fi
else
    print_ok "'${log}' permissions OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.4 Ensure 'slow_query_log' Has Appropriate Permissions (Automated)"
log=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'slow_query_log';")
if [ "x${log}" = "xOFF" ]
then
	print_ok "slow query is disabled"
else
    print_err "Error : slow_query set to ${log}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		#Disable slow query is compliant
		#mysql_call "SET PERSIST slow_query_log = OFF;"
		print_info "If slow query is enable, prefer configuring log files"
		#chmod 660 ${log} 
		#chown ${MYSQL_USER}:${MYSQL_USER} ${log}
	fi
fi

# ---------------------------------------------------------------------------------------------------
echo "  3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions (Automated)"
log=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'relay_log_basename';")
if [ "x${log}" = "x" ]
then
    print_err "'relay_log_basename' disabled"
else
	ret=$(ls -l | egrep "^-(?![r|w]{2}-[r|w]{2}----.*${MYSQL_USER}\s*${MYSQL_USER}).*${log}.*$")
	if [ "x${ret}" = "x" ]
	then
	    print_err "'${log}' permissions Error"
		if [ "x${REMEDIATE}" = "xYES" ]
		then
			chmod 660 ${log} 
			chown ${MYSQL_USER}:${MYSQL_USER} ${log}
		fi
	else
    		print_ok "'${log}' permissions OK"
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.6 Ensure 'general_log_file' Has Appropriate Permissions (Automated)"
ret=$(mysql_call "select @@general_log;")
if [ "x${ret}" = "x0" ] || [ "x${ret}" = "xOFF" ]
then
    print_ok "General log is disabled"
else
	print_err "general_log is enabled, please review the following file permissions"
	mysql_call "show variables like 'general_log_file';"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		# Diabling general_log is compliant too
		#mysql_call "SET PERSIST @@GENERAL_LOG=OFF"
		print_info "If general_log is enable, configure the log files"
		#chmod 600 <general_log_file> 
		#chown mysql:mysql <general_log_file>
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.7 Ensure SSL Key Files Have Appropriate Permissions (Automated)"
# MySQL
#mysql_call "SELECT * FROM information_schema.global_variables WHERE REGEXP_LIKE(VARIABLE_NAME,'^.*ssl_(ca|capath|cert|crl|crlpath|key)$') AND VARIABLE_VALUE <> '';"
# MariaDB
ssl=$(mysql_call "SELECT variable_value FROM information_schema.global_variables WHERE VARIABLE_NAME RLIKE '^.*ssl_(ca|capath|cert|crl|crlpath|key)$' AND VARIABLE_VALUE <> '';")
if [ "x${ssl}" = "x" ]
then
    print_err "SSL is not configured"
else
	for s in ${ssl}
	do
		ret=$(ls -l ${s} | egrep "^-(?!r-{8}.*${MYSQL_USER}\s*${MYSQL_USER}).*$")
		if [ "x${ret}" = "x" ]
		then
    			print_ok "'${s}' OK"
		else
    			print_err "'${s}' wrong permission/user"
			if [ "x${REMEDIATE}" = "xYES" ]
			then
				chown ${MYSQL_USER}:${MYSQL_USER} ${s} 
				chmod 400 ${s}
			fi
		fi
	done
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.8 Ensure Plugin Directory Has Appropriate Permissions (Automated)"
plugin=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'plugin_dir';")
ret=$(ls -ld ${plugin} | grep "dr-xr-x---\|dr-xr-xr--" | grep "plugin")
if [ "x${ret}" = "x" ]
then
    print_err "${plugin} file got wrong permissions"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		chmod 550 ${plugin} #(or use 554) 
		chown ${MYSQL_USER}:${MYSQL_USER} ${plugin}
	fi
else
    print_ok "${plugin} permissions OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.9 Ensure 'audit_log_file' Has Appropriate Permissions (Automated)"
# Mysql
#ret=$(mysql_call "show global variables where variable_name='audit_log_file';")
# MariaDB
log=$(mysql_call "select variable_value from information_schema.global_variables where variable_name='server_audit_file_path';")
if [ "x${log}" = "x" ]
then
    print_err "'audit' plugin may not be installed"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		print_warn 'Manually install audit plugin'
		echo "plugin_load_add=server_audit" >> ${MYSQL_CONFIG_FILE}
		echo "server_audit_file_path='${MYSQL_DATADIR}/server_audit.log'" >> ${MYSQL_CONFIG_FILE}
		echo "server_audit_logging='FORCE_PLUS_PERMANENT'" >> ${MYSQL_CONFIG_FILE}
	fi
else
    print_ok "Audit plugin is installed"
    	# Original from CIS
	#ret=$(ls -l ${log} | egrep "^-([rw-]{2}-){2}---[ \t]*[0-9][ \t]*${MYSQL_USER}[ \t]*${MYSQL_USER}.*$")
	# RHEL 9
    ret=$(ls -l ${log} | egrep "^-([rw-]{2}-){2}---\.[ \t]*[0-9][ \t]*${MYSQL_USER}[ \t]*${MYSQL_USER}.*$")
	if [ "x${ret}" = "x" ]
	then
    		print_err "${log} wrong permission"
		if [ "x${REMEDIATE}" = "xYES" ]
		then
			chmod 660 ${log}
			chown ${MYSQL_USER}:${MYSQL_USER} ${log}
		fi
	else
    		print_ok "${log} permissions OK"
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.10 Secure MySQL Keyring (Automated)"
print_info "Keyring is considered less secure than certificate => check that there is no keyring plugin"
ret=$(grep "keyring" ${MYSQL_CONFIG_FILE})
if [ "x${ret}" = "x" ]
then
    print_ok "'keyring' keyword not present in ${MYSQL_CONFIG_FILE}"
else
    print_err "Keyring present in ${MYSQL_CONFIG_FILE}"
fi
# ---------------------------------------------------------------------------------------------------
echo "4 General "
echo "  4.1 Ensure the Latest Security Patches are Applied (Manual)"
mysql_call "SHOW VARIABLES WHERE Variable_name LIKE 'version';"
print_info "Check that this is the latest version"
# ---------------------------------------------------------------------------------------------------
echo "  4.2 Ensure Example or Test Databases are Not Installed on Production Servers (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.3 Ensure 'allow-suspicious-udfs' is Set to 'OFF' (Automated)"
ret=$(my_print_defaults mysqld | grep allow-suspicious-udfs)
if [ "x${ret}" = "x" ]
then
    print_ok "OK"
else
    print_err "allow-suspicious-udfs is configured"
fi
# ---------------------------------------------------------------------------------------------------
echo "  4.4 Harden Usage for 'local_infile' on MySQL Clients (Automated)"
ret=$(mysql_call "Select variable_value from information_schema.global_variables where variable_name='local_infile';")
if [ "x${ret}" = "xON" ]
then
	print_err "'local_infile' is enabled"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "local-infile=0" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'local_infile' is disabled"
fi
# ---------------------------------------------------------------------------------------------------
echo "  4.5 Ensure 'mysqld' is Not Started With '--skip-grant-tables' (Automated)"
ret=`grep "skip-grant-tables = FALSE" ${MYSQL_CONFIG_FILE}`
if [ "x${ret}" = "x" ]
then
	print_err "'skip-grant-table' not found in ${MYSQL_CONFIG_FILE}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "skip-grant-tables = FALSE" >> ${MYSQL_CONFIG_FILE}
	fi
else
    print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  4.6 Ensure Symbolic Links are Disabled (Automated)"
ret=$(mysql_call "Select variable_value from information_schema.global_variables where variable_name='have_symlink';")
if [ "x${ret}" = "xDISABLED" ]
then
	print_ok "OK"
else
	print_err "Symlink enabled"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "skip-symbolic-links = YES" >> ${MYSQL_CONFIG_FILE}
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "  4.7 Ensure the 'daemon_memcached' Plugin is Disabled (Automated)"
print_info "'daemon_memcached' not present in MariaDB"
#ret=$(mysql_call "SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME='daemon_memcached';")
#if [ "x${ret}" = "x" ]
#then
#	print_ok "OK"
#else
#	print_err "daemon_memcached enabled"
#	if [ "x${REMEDIATE}" = "xYES" ]
#	then
#		mysql_call "uninstall plugin daemon_memcached;"
#	fi
#fi
# ---------------------------------------------------------------------------------------------------
echo "  4.8 Ensure the 'secure_file_priv' is Configured Correctly (Automated)"
mysql_call "SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv';"
print_info "The Value should either contain NULL (thus is disabled entirely) or a valid path. If set to an empty string this is a fail."
# ---------------------------------------------------------------------------------------------------
echo "  4.9 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES' (Automated)"
val=$(mysql_call "select variable_value from information_schema.global_VARIABLES where variable_name = 'sql_mode';")
ret=$(mysql_call "select variable_value from information_schema.global_VARIABLES where variable_name = 'sql_mode' AND variable_value like '%STRICT_ALL_TABLES%';")
if [ "x${ret}" = "x" ]
then
	print_err "'sql_mode' incorrect : ${val}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "sql-mode=${val},STRICT_ALL_TABLES" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'sql_mode' set to ${val}"
fi
# ---------------------------------------------------------------------------------------------------
echo "  4.10 Use MySQL TDE for At-Rest Data Encryption (Automated)"
bin=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'encrypt_binlog';")
inno=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'innodb_encrypt_log';")
innotable=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'innodb_encrypt_tables';")
innotmp=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'innodb_encrypt_temporary_tables';")
aria=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'aria_encrypt_tables';")
tmp=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'encrypt_tmp_disk_tables';")
if [ ! "x${bin}" = "xON" ]
then
	print_err "'encrypt_binlog' incorrect : ${bin}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "encrypt_binlog=ON" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'encrypt_binlog' OK"
fi
if [ ! "x${inno}" = "xON" ]
then
	print_err "'innodb_encrypt_log' incorrect : ${inno}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "innodb_encrypt_log=ON" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'innodb_encrypt_log' OK"
fi
if [ ! "x${innotmp}" = "xON" ]
then
	print_err "'innodb_encrypt_temporary_tables' incorrect : ${innotmp}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "innodb_encrypt_temporary_tables=ON" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'innodb_encrypt_temporary_tables' OK"
fi
if [ ! "x${innotable}" = "xON" ]
then
	print_err "'innodb_encrypt_tables' incorrect : ${innotable}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "innodb_encrypt_tables=ON" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'innodb_encrypt_tables' OK"
fi
if [ ! "x${aria}" = "xON" ]
then
	print_err "'aria_encrypt_tables' incorrect : ${aria}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "aria_encrypt_tables=ON" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'aria_encrypt_tables' OK"
fi
if [ ! "x${tmp}" = "xON" ]
then
	print_err "'encrypt_tmp_disk_tables' incorrect : ${tmp}"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "encrypt_tmp_disk_tables=ON" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'encrypt_tmp_disk_tables' OK"
fi
print_warn "Please check that tables/logs should be encrypted or not"
print_warn "Don't forget to manually set encryption keys by adding the following lines in ${MYSQL_CONFIG_FILE}"
print_warn "plugin_load_add=file_key_management"
print_warn "file_key_management='FORCE_PLUS_PERMANENT'"
print_warn "file_key_management_filename=/var/lib/mysql/keyfile.enc"
print_warn "file_key_management_filekey=FILE:/var/lib/mysql/keyfile.key"
print_warn "file_key_management_encryption_algorithm=AES_CTR"

# ---------------------------------------------------------------------------------------------------
echo "5 MySQL Permissions"
echo "  5.1 Ensure Only Administrative Users Have Full Database Access (Manual)"
ret=$(mysql_call "select grantee from information_schema.user_privileges;")
err=0
print_info "Administrator are 'mariadb.sys@localhost', 'mysql@localhost' and 'root@localhost'"
for u in ${ret}
do
  if [ ! "x${u}" = "x'mysql'@'localhost'" ] && [ ! "x${u}" = "x'mariadb.sys'@'localhost'" ] && [ ! "x${u}" = "x'root'@'localhost'" ]
  then
	  err=1
	  print_err "${u} is not an administrative user"
  fi
done
if [ "${err}" = "0" ]
then
	print_ok "All users OK"
fi	
# ---------------------------------------------------------------------------------------------------
echo "  5.2 Ensure 'FILE' is Not Granted to Non-Administrative Users (Manual)"
print_info "Test done in 5.6"
echo "  5.3 Ensure 'PROCESS' is Not Granted to Non-Administrative Users (Manual)"
print_info "Test done in 5.6"
echo "  5.4 Ensure 'SUPER' is Not Granted to Non-Administrative Users (Manual)"
print_info "Test done in 5.6"
echo "  5.5 Ensure 'SHUTDOWN' is Not Granted to Non-Administrative Users (Manual)"
print_info "Test done in 5.6"
echo "  5.6 Ensure 'CREATE USER' is Not Granted to Non-Administrative Users (Manual)"
ret=$(mysql_call "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE IN ('FILE', 'PROCESS', 'SUPER', 'SHUTDOWN', 'CREATE USER');")
err=0
print_info "Administrator are 'mariadb.sys@localhost', 'mysql@localhost' and 'root@localhost'"
for u in ${ret}
do
  if [ ! "x${u}" = "x'mysql'@'localhost'" ] && [ ! "x${u}" = "x'mariadb.sys'@'localhost'" ] && [ ! "x${u}" = "x'root'@'localhost'" ]
  then
	  err=1
	  print_err "${u} is not an administrative user"
  fi
done
if [ "${err}" = "0" ]
then
	print_ok "All users OK"
fi	
# ---------------------------------------------------------------------------------------------------
echo "  5.7 Ensure 'GRANT OPTION' is Not Granted to Non-Administrative Users (Manual)"
ret=$(mysql_call "SELECT DISTINCT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE = 'YES';")
err=0
print_info "Administrator are 'mariadb.sys@localhost', 'mysql@localhost' and 'root@localhost'"
for u in ${ret}
do
  if [ ! "x${u}" = "x'mysql'@'localhost'" ] && [ ! "x${u}" = "x'mariadb.sys'@'localhost'" ] && [ ! "x${u}" = "x'root'@'localhost'" ]
  then
	  err=1
	  print_err "${u} is not an administrative user"
  fi
done
if [ "${err}" = "0" ]
then
	print_ok "All users OK"
fi	
# ---------------------------------------------------------------------------------------------------
echo "  5.8 Ensure 'REPLICATION SLAVE' is Not Granted to Non-Administrative Users (Manual)"
ret=$(mysql_call "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'REPLICATION SLAVE';")
err=0
print_info "Administrator are 'mariadb.sys@localhost', 'mysql@localhost' and 'root@localhost'"
for u in ${ret}
do
  if [ ! "x${u}" = "x'mysql'@'localhost'" ] && [ ! "x${u}" = "x'mariadb.sys'@'localhost'" ] && [ ! "x${u}" = "x'root'@'localhost'" ]
  then
	  err=1
	  print_err "${u} is not an administrative user"
  fi
done
if [ "${err}" = "0" ]
then
	print_ok "All users OK"
fi	
# ---------------------------------------------------------------------------------------------------
echo "  5.9 Ensure DML/DDL Grants are Limited to Specific Databases and Users (Manual)"
mysql_call "SELECT User,Host,Db FROM mysql.db WHERE Select_priv='Y' OR Insert_priv='Y' OR Update_priv='Y' OR Delete_priv='Y' OR Create_priv='Y' OR Drop_priv='Y' OR Alter_priv='Y';"
print_info "Ensure all users returned are permitted to have these privileges on the indicated databases."
# ---------------------------------------------------------------------------------------------------
echo "  5.10 Securely Define Stored Procedures and Functions DEFINER and INVOKER (Manual)"
mysql_call "SHOW PROCEDURE STATUS; SHOW FUNCTION STATUS"
print_info "Inspect Definer and Invoker security types."
print_info "If DEFINER is a powerful user consider that user's permissions."
print_info "If INVOKER then the rights for the stored procedure or function are that of the user executing these."
# ---------------------------------------------------------------------------------------------------
echo "6 Auditing and Logging"
# ---------------------------------------------------------------------------------------------------
echo "  6.1 Ensure 'log_error' is configured correctly (Automated)"
ret=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'log_error';")
if [ "x${ret}" = "x" ] || [ "x${ret}" = "x./stderr.err" ]
then
	print_err "log-error not configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "log-error=/var/log/mariadb/mariadb.log" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  6.2 Ensure Log Files are Stored on a Non-System Partition (Automated)"
ret=$(mysql_call "SELECT @@global.log_bin_basename;")
print_warn "'log_bin_basename'=${ret}"
print_info "Ensure the value returned does not indicate root (/), /var, or /usr."
# ---------------------------------------------------------------------------------------------------
echo "  6.3 Ensure 'log_error_verbosity' is Set to '2' (Automated)"
mysql_call "SHOW GLOBAL VARIABLES LIKE 'log_error_verbosity';"
print_info "Ensure the Value returned equals 2."
# ---------------------------------------------------------------------------------------------------
echo "  6.4 Ensure 'log-raw' is Set to 'OFF' (Automated)"
ret=$(cat ${MYSQL_CONFIG_FILE} | grep "log-raw=OFF")
if [ "x${ret}" = "x" ]
then
	print_err "log-raw not configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "log-raw=OFF" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  6.5 Ensure Audit Filters Capture Connection Attempts (Manual)"
# MariaDB
ret=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'server_audit_excl_users';")
if [ "x${ret}" = "x" ]
then
	print_ok "No excluded users from 'server_audit_excl_users'"
else
	print_err "Some users are excluded : ${ret}"
fi
# MySQL
#mysql_call "SELECT * FROM mysql.audit_log_filter;"
#mysql_call "SELECT * FROM mysql.audit_log_user;"
# ---------------------------------------------------------------------------------------------------
echo "  6.6 Ensure ALL Events are Audited (Automated)"
# MySQL
#mysql_call "SELECT * FROM mysql.audit_log_filter;"
#mysql_call "SELECT * FROM mysql.audit_log_user;"
ret=$(grep "filter" ${MYSQL_CONFIG_FILE})
if [ "x${ret}" = "x" ]
then
	print_ok "No filter found in ${MYSQL_CONFIG_FILE}"
else
	print_err "'filter' keyword found in ${MYSQL_CONFIG_FILE}, please review this file"
fi
# ---------------------------------------------------------------------------------------------------
echo "  6.7 Set audit_log_strategy to SYNCHRONOUS or SEMISYNCRONOUS (Automated)"
ret=$(mysql_call "SHOW GLOBAL VARIABLES LIKE 'audit_log_strategy';")
if [ "x${ret}" = "xSYNCHRONOUS" ] || [ "x${ret}" = "xSEMISYNCHRONOUS" ]
then
	print_ok "OK"
else
	print_err "audit strategy incorrect"
	print_warn "'audit_log_strategy' not present in MariaDB"
	#if [ "x${REMEDIATE}" = "xYES" ]
	#then
	#	echo "audit_log_strategy='SEMISYNCHRONOUS'" >> ${MYSQL_CONFIG_FILE}
	#fi
fi
# ---------------------------------------------------------------------------------------------------
echo "  6.8 Ensure the Audit Plugin Can't be Unloaded (Automated)"
# MySQL
#ret=$(mysql_call "SELECT LOAD_OPTION FROM information_schema.plugins WHERE PLUGIN_NAME='audit_log';")
# MariaDB
ret=$(mysql_call "SELECT LOAD_OPTION FROM information_schema.plugins WHERE PLUGIN_NAME='server_audit';")
if [ "x${ret}" = "xFORCE_PLUS_PERMANENT" ]
then
	print_ok "OK"
else
	print_err "audit plugin can be unloaded"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "server_audit='FORCE_PLUS_PERMANENT'" >> ${MYSQL_CONFIG_FILE}
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "7 Authentication"
# ---------------------------------------------------------------------------------------------------
echo "  7.1 Ensure default_authentication_plugin is Set to a Secure Option (Automated)"
ret=$(mysql_call "SHOW VARIABLES WHERE Variable_name = 'default_authentication_plugin';")
if [ "x${ret}" = "xmysql_native_password." ]
then
	print_err "default_authentication_plugin error"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "default_authentication_plugin=caching_sha2_password" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  7.2 Ensure Passwords are Not Stored in the Global Configuration (Automated)"
ret=$(grep "^password\s*=.*$" ${MYSQL_CONFIG_FILE})
if [ "x${ret}" = "x" ]
then
	print_ok "'password=' not found in ${MYSQL_CONFIG_FILE}"
	print_warn "Please review ${MYSQL_CONFIG_FILE} to make sure there is no plain text password"
else
	print_err "default_authentication_plugin error"
fi
# ---------------------------------------------------------------------------------------------------
echo "  7.3 Ensure Passwords are Set for All MySQL Accounts (Automated)"
ret=$(mysql_call "SELECT User,host FROM mysql.user WHERE (plugin IN('mysql_native_password', 'mysql_old_password','') AND (LENGTH(authentication_string) = 0 OR authentication_string IS NULL)) OR (plugin='sha256_password' AND LENGTH(authentication_string) = 0);")
if [ "x${ret}" = "x" ]
then
	print_ok "OK"
else
	print_err "Some user have blank password"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		sleep 0
		# mysql_call "ALTER USER <user>@<host> IDENTIFIED BY RANDOM PASSWORD PASSWORD EXPIRE;"
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "  7.4 Set 'default_password_lifetime' to Require a Yearly Password Change (Automated)"
ret=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'default_password_lifetime';")
if [ "x${ret}" = "x0" ]
then
	print_err "default_password_lifetime is not configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		sleep 0
		# SET GLOBAL default_password_lifetime=365"
	fi
else
	print_ok "OK"
fi
# ---------------------------------------------------------------------------------------------------
echo "  7.5 Ensure Password Complexity Policies are in Place (Automated)"
# MariaDB
ret=$(mysql_call "select variable_value from information_schema.global_variables where variable_name = 'simple_password_check_minimal_length'")
if [ "x${ret}" = "x" ]
then
	print_err "'simple_password_check' plugin not installed fail"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "plugin_load_add=simple_password_check" >> ${MYSQL_CONFIG_FILE}
		echo "simple_password_check='FORCE_PLUS_PERMANENT'" >> ${MYSQL_CONFIG_FILE}
	fi	
else
	print_ok "'simple_password_check' installed"
	print_warn "Review following values according to your security requirements"
	mysql_call "select variable_value, variable_name from information_schema.global_variables where variable_name like 'simple_password%';"
fi
# MySQL
#ret=$(mysql_call "select * from mysql.component where component_urn like '%validate_password';")
#if [ "x${ret}" = "x" ]
#then
#	print_err "Password complexity fail"
#	mysql_call "SHOW VARIABLES LIKE 'validate_password%';"
#	if [ "x${REMEDIATE}" = "xYES" ]
#	then
#		echo ''
#		# Manually done
#	fi	
#else
#	print_ok "OK"
#fi
# ---------------------------------------------------------------------------------------------------
echo "  7.6 Ensure No Users Have Wildcard Hostnames (Automated)"
ret=$(mysql_call "SELECT user, host FROM mysql.user WHERE host = '%';")
if [ "x${ret}" = "x" ]
then
	print_ok "OK"
else
	print_err "Error"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		sleep 0
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "  7.7 Ensure No Anonymous Accounts Exist (Automated)"
ret=$(mysql_call "SELECT user,host FROM mysql.user WHERE user = '';")
if [ "x${ret}" = "x" ]
then
	print_ok "OK"
else
	print_err "Error"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		sleep 0
	fi
fi
# ---------------------------------------------------------------------------------------------------
echo "8  Network"
# ---------------------------------------------------------------------------------------------------
echo "  8.1 Ensure 'require_secure_transport' is Set to 'ON' and/or 'have_ssl' is Set to 'YES' (Automated)"
ret=$(mysql_call "select @@require_secure_transport;")
if [ "x${ret}" = "xON" ] || [ "x${ret}" = "x1" ]
then
	print_ok "OK"
else
	print_err "'require_secure_transport' is not configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "require_secure_transport=ON" >> ${MYSQL_CONFIG_FILE}
		# MySQL
		#mysql_call "set persist require_secure_transport=ON;"
	fi
fi
mysql_call "SHOW variables WHERE variable_name IN ('have_ssl', 'have_openssl');"
print_info "Check if one the 2 above is set to YES"
# ---------------------------------------------------------------------------------------------------
echo "  8.2 Ensure 'ssl_type' is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users (Automated)"
mysql_call "SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN ('::1', '127.0.0.1', 'localhost');"
print_warn "Ensure the ssl_type for above users returned is equal to X509, or SPECIFIED."
if [ "x${REMEDIATE}" = "xYES" ]
then
	sleep 0
	# mysql_call "ALTER USER 'my_user'@'app1.example.com' REQUIRE X509;"
fi
# ---------------------------------------------------------------------------------------------------
echo "  8.3 Set Maximum Connection Limits for Server and per User (Manual)"
max=$(mysql_call "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME LIKE 'max_connections';")
user=$(mysql_call "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'max_user_connections';")
if [ "x${max}" = "x0" ]
then
	print_err "'max_connections' is not configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "max-_connections=151" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'max_connections' set to ${max}"
fi
if [ "x${user}" = "x0" ]
then
	print_err "'max_user_connections' is not configured"
	if [ "x${REMEDIATE}" = "xYES" ]
	then
		echo "max_user_connections=151" >> ${MYSQL_CONFIG_FILE}
	fi
else
	print_ok "'max_user_connections' set to ${user}"
fi

print_warn "Review the max connections to fit your requirements."
# ---------------------------------------------------------------------------------------------------
echo "9  Replication"
echo "  9.1 Ensure Replication Traffic is Secured (Manual)"
print_warn "Manual"
# ---------------------------------------------------------------------------------------------------
echo "  9.2 Ensure 'SOURCE_SSL_VERIFY_SERVER_CERT' is Set to 'YES' or '1' (Automated)"
mysql_call "select ssl_verify_server_cert from mysql.slave_master_info;"
print_info "Verify the value of ssl_verify_server_cert is 1."
# ---------------------------------------------------------------------------------------------------
echo "  9.3 Ensure 'master_info_repository' is Set to 'TABLE' (Automated)"
mysql_call "SHOW GLOBAL VARIABLES LIKE 'master_info_repository';"
print_info "The result should be TABLE instead of FILE."
print_info "Note: There also should not be a source.info or master.info file in the datadir."
# ---------------------------------------------------------------------------------------------------
echo "  9.4 Ensure 'super_priv' is Not Set to 'Y' for Replication Users (Automated)"
mysql_call "select user, host from mysql.user where user='repl' and Super_priv = 'Y';"
if [ "x${ret}" = "xON" ] || [ "x${ret}" = "x" ]
then
	print_ok "OK"
else
	print_err "Error"
fi
mysql_call "select * from mysql.user where user='repl'\G"

mysql_call "select PRIV from mysql.global_grants where user like QUOTE('repl')\G"
# ---------------------------------------------------------------------------------------------------
echo "10  MySQL InnoDB Cluster / Group Replication"
echo "  10.1 Ensure All Group Replication Traffic is Secured (Manual)"
print_warn "Manual test"
echo "  10.2 Allowlist Approved Servers Belonging to a MySQL InnoDB Cluster (Manual)"
print_warn "Manual test"

echo "==== Script finished with ${err_count} error(s) ===="

# Restarting to take account of modified config file
if [ "x${REMEDIATE}" = "xYES" ]
then
	print_warn "Restarting MySQL daemon"
	systemctl restart ${MYSQL_SERVICE}
fi
