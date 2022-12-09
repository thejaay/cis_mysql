#!/bin/bash
#set -x
MYSQL_BIN="mysql"
# Consider using command line argument for username/password
MYSQL_OPTS="--skip-column-names --silent --raw"
# /!\ WARNING /!\ Remediation will apply the changes even if rule is already correct. Current values will be overwritten by default expected values
REMEDIATE="NO"
#REMEDIATE="YES"

MYSQL_CONFIG_FILE="/etc/my.cnf"
MYSQL_USER="mysql"

ERR_COLOR='\033[0;31m'
OK_COLOR='\033[0;32m'
INFO_COLOR='\033[0;36m'
NC='\033[0m' # No Color

# Wrapper for SQL query
mysql_call()
{
 ${MYSQL_BIN} ${MYSQL_OPTS} -e "${1}"
}

# Format error message
print_err()
{
  echo -e "      ${ERR_COLOR} ${1} ${NC}"
}

# Format success message
print_ok()
{
  echo -e "      ${OK_COLOR} ${1} ${NC}"
}

# Format info message
print_info()
{
  echo -e "      ${INFO_COLOR} ${1} ${NC}"
}

echo "1 Operating System Level Configuration"
echo "  1.1 Place Databases on Non-System Partitions (Manual)"
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
    print_err "MySQL history not disabled for all users"
fi
if [ "x${REMEDIATE}" = "xYES" ]
then
    find /home -type d -maxdepth 1 -exec ln -ls {} /dev/null {}/.mysql_history \;
	ln -ls /dev/null /root/.mysql_history
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
else
    print_ok "OK"
fi
if [ "x${REMEDIATE}" = "xYES" ]
then
	usermod -s /bin/false mysql
	# Also OK
	# usermod -s /bin/nologin mysql
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
exit
# ---------------------------------------------------------------------------------------------------
echo "  1.7 Ensure MySQL is Run Under a Sandbox Environment (Manual)"
echo "2  Installation and Planning"
echo "  2.1 Backup and Disaster Recovery"
echo "    2.1.1 Backup Policy in Place (Manual)"
echo "    2.1.2 Verify Backups are Good (Manual)"
echo "    2.1.3 Secure Backup Credentials (Manual)"
echo "    2.1.4 The Backups Should be Properly Secured (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "    2.1.5 Point-in-Time Recovery (Automated)"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - Log Expiration' as Note FROM performance_schema.global_variables where variable_name = 'binlog_expire_logs_seconds';"
# ---------------------------------------------------------------------------------------------------
echo "    2.1.6 Disaster Recovery (DR) Plan (Manual)"
echo "    2.1.7 Backup of Configuration and Related Files (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "  2.2 Data Encryption 2.2.1  Ensure Binary and Relay Logs are Encrypted (Automated)"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - At Rest Encryption' as Note FROM performance_schema.global_variables where variable_name = 'binlog_encryption';"
if [ "x${REMEDIATE}" = "xYES" ]
then
	# mysql_call "SET GLOBAL binlog_encryption=ON;"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.3 Dedicate the Machine Running MySQL (Manual)"
echo "  2.4 Do Not Specify Passwords in the Command Line (Manual)"
echo "  2.5 Do Not Reuse Usernames (Manual)"
echo "  2.6 Ensure Non-Default, Unique Cryptographic Material is in Use (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "  2.7 Ensure 'password_lifetime' is Less Than or Equal to '365 ' (Automated)"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME like 'default_password_lifetime';"
if [ "x${REMEDIATE}" = "xYES" ]
then
	#mysql_call "set persist default_password_lifetime = 365;"
fi
print_info "When the global password lifetime is less than or equal to 365, or not configured, each user account shall be checked by executing the following command:"
mysql_call "SELECT user, host, password_lifetime from mysql.user where password_lifetime = 0 OR password_lifetime >= 365;"
if [ "x${REMEDIATE}" = "xYES" ]
then
	print_info "Manually run \"ALTER USER '<username>'@'<localhost>' PASSWORD EXPIRE INTERVAL 365 DAY;\" for each faulty users"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.8 Ensure Password Resets Require Strong Passwords (Automated)"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME in ('password_history', 'password_reuse_interval');"
if [ "x${REMEDIATE}" = "xYES" ]
then
	mysql_call "SET PERSIST password_history = 5;"
	mysql_call "SET PERSIST password_reuse_interval = 365;"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.9 Require Current Password for Password Reset (Automated)"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables where VARIABLE_NAME in ('password_require_current');"
if [ "x${REMEDIATE}" = "xYES" ]
then
	mysql_call "SET PERSIST password_require_current=ON;"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.10 Use Dual Passwords to Enable Higher Frequency Password Rotation (Manual)"
echo "  2.11 Lock Out Accounts if Not Currently in Use (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "  2.12 Ensure AES Encryption Mode for AES_ENCRYPT/AES_DECRYPT is Configured Correctly (Automated)"
mysql_call "select @@block_encryption_mode;"
if [ "x${REMEDIATE}" = "xYES" ]
then
    echo "block_encryption_mode=aes-256-cbc" >> ${MYSQL_CONFIG_FILE}
	# Also OK
	# mysql_call "set persist block_encryption_mode='aes-256-cbc'"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.13 Ensure Socket Peer-Credential Authentication is Used Appropriately (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "  2.14 Ensure MySQL is Bound to an IP Address (Automated)"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME = 'bind_address';"
if [ "x${REMEDIATE}" = "xYES" ]
then
    print_info "Run following command echo \"bind_address=X.X.X.X\" >> ${MYSQL_CONFIG_FILE}"
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.15 Limit Accepted Transport Layer Security (TLS) Versions (Automated)"
mysql_call "select @@tls_version;"
print_info "TLS versions must be TLS1.2 and/or TLSv1.3 (but not TLSv1 nor TLSv1.1)"
if [ "x${REMEDIATE}" = "xYES" ]
then
    echo "tls_version=TLSv1.2,TLSv1.3" >> ${MYSQL_CONFIG_FILE}
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.16 Require Client-Side Certificates (X.509) (Automated)"
mysql_call "select user, host, ssl_type from mysql.user where user not in ('mysql.infoschema', 'mysql.session', 'mysql.sys');"
print_info "ssl_type must be X509 or SSL for all users"
# ---------------------------------------------------------------------------------------------------
echo "  2.17 Ensure Only Approved Ciphers are Used (Automated)"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME IN ('ssl_cipher', 'tls_ciphersuites');"
if [ "x${REMEDIATE}" = "xYES" ]
then
	echo "tls_ciphersuites='TLS_AES_256_GCM_SHA384'" >> ${MYSQL_CONFIG_FILE}
	echo "ssl_cipher='ECDHE-ECDSA-AES128-GCM-SHA256'" >> ${MYSQL_CONFIG_FILE}
fi
# ---------------------------------------------------------------------------------------------------
echo "  2.18 Implement Connection Delays to Limit Failed Login Attempts (Automated)"
mysql_call "SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE 'connection%';"
print_info "Following plugins must be presents :"
print_info "CONNECTION_CONTROL | ACTIVE"
print_info "CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS | ACTIVE"
mysql_call "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'connection_control%';"
print_info "If connection_control_failed_connections_threshold is less than 5 (attempts), this is a fail."
print_info "If connection_control_min_connection_delay is less than 60000 (ms - 1 minute), this is a fail."
print_info "Max delay connection_control_max_connection_delay is 0 or less than 1920000 (ms, 32 minutes) a, this is a fail."
mysql_call "select host, user, JSON_EXTRACT(user_attributes, '$.Password_locking.failed_login_attempts') as failed_login_attempts from mysql.user;"
print_info "If failed login attempts is less than 12 this is a fail."
# ---------------------------------------------------------------------------------------------------
echo "3 File Permissions"
# ---------------------------------------------------------------------------------------------------
echo "  3.1 Ensure 'datadir' Has Appropriate Permissions (Automated)"
dir=$(mysql_call "show variables where variable_name = 'datadir';")
ret=${sudo ls -ld ${dir} | grep "drwxr-x---.*mysql.*mysql"}
if [ "x${ret}" = "x" ]
then
    print_ok "OK"
else
    print_err "Datadir is not correctly configured"
fi
if [ "x${REMEDIATE}" = "xYES" ]
then
	chmod 750 ${dir}
	chown ${MYSQL_USER}:${MYSQL_USER} ${dir}
fi
# ---------------------------------------------------------------------------------------------------
echo "  3.2 Ensure 'log_bin_basename' Files Have Appropriate Permissions (Automated)"
log=$(mysql_call "show variables like 'log_bin_basename';")

# ---------------------------------------------------------------------------------------------------
echo "  3.3 Ensure 'log_error' Has Appropriate Permissions (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  3.4 Ensure 'slow_query_log' Has Appropriate Permissions (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  3.6 Ensure 'general_log_file' Has Appropriate Permissions (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  3.7 Ensure SSL Key Files Have Appropriate Permissions (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  3.8 Ensure Plugin Directory Has Appropriate Permissions (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  3.9 Ensure 'audit_log_file' Has Appropriate Permissions (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  3.10 Secure MySQL Keyring (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "4 General "
echo "  4.1 Ensure the Latest Security Patches are Applied (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "  4.2 Ensure Example or Test Databases are Not Installed on Production Servers (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.3 Ensure 'allow-suspicious-udfs' is Set to 'OFF' (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.4 Harden Usage for 'local_infile' on MySQL Clients (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.5 Ensure 'mysqld' is Not Started With '--skip-grant-tables' (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.6 Ensure Symbolic Links are Disabled (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.7 Ensure the 'daemon_memcached' Plugin is Disabled (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.8 Ensure the 'secure_file_priv' is Configured Correctly (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.9 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES' (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  4.10 Use MySQL TDE for At-Rest Data Encryption (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "5 MySQL Permissions"
echo "  5.1 Ensure Only Administrative Users Have Full Database Access (Manual)"
mysql_call "select * from information_schema.user_privileges where grantee not like ('\'mysql.%localhost\'');"
print_info "Ensure all users returned are administrative users with minimal privileges required."
# ---------------------------------------------------------------------------------------------------
echo "  5.2 Ensure 'FILE' is Not Granted to Non-Administrative Users (Manual)"
echo "  5.3 Ensure 'PROCESS' is Not Granted to Non-Administrative Users (Manual)"
echo "  5.4 Ensure 'SUPER' is Not Granted to Non-Administrative Users (Manual)"
echo "  5.5 Ensure 'SHUTDOWN' is Not Granted to Non-Administrative Users (Manual)"
echo "  5.6 Ensure 'CREATE USER' is Not Granted to Non-Administrative Users (Manual)"
mysql_call "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE IN ('FILE', 'PROCESS', 'SUPER', 'SHUTDOWN', 'CREATE USER');"
print_info "Check that only administrators are returned"
# ---------------------------------------------------------------------------------------------------
echo "  5.7 Ensure 'GRANT OPTION' is Not Granted to Non-Administrative Users (Manual)"
mysql_call "SELECT DISTINCT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE = 'YES';"
print_info "Check that only administrators are returned"
# ---------------------------------------------------------------------------------------------------
echo "  5.8 Ensure 'REPLICATION SLAVE' is Not Granted to Non-Administrative Users (Manual)"
mysql_call "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'REPLICATION SLAVE';"
print_info "Check that only administrators are returned"
# ---------------------------------------------------------------------------------------------------
echo "  5.9 Ensure DML/DDL Grants are Limited to Specific Databases and Users (Manual)"
mysql_call "SELECT User,Host,Db FROM mysql.db WHERE Select_priv='Y' OR Insert_priv='Y' OR Update_priv='Y' OR Delete_priv='Y' OR Create_priv='Y' OR Drop_priv='Y' OR Alter_priv='Y';"
print_info "Ensure all users returned are permitted to have these privileges on the indicated databases."
# ---------------------------------------------------------------------------------------------------
echo "  5.10 Securely Define Stored Procedures and Functions DEFINER and INVOKER (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "6 Auditing and Logging"
# ---------------------------------------------------------------------------------------------------
echo "  6.1 Ensure 'log_error' is configured correctly (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  6.2 Ensure Log Files are Stored on a Non-System Partition (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  6.3 Ensure 'log_error_verbosity' is Set to '2' (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  6.4 Ensure 'log-raw' is Set to 'OFF' (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  6.5 Ensure Audit Filters Capture Connection Attempts (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "  6.6 Ensure ALL Events are Audited (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  6.7 Set audit_log_strategy to SYNCHRONOUS or SEMISYNCRONOUS (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  6.8 Ensure the Audit Plugin Can't be Unloaded (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "7 Authentication"
# ---------------------------------------------------------------------------------------------------
echo "  7.1 Ensure default_authentication_plugin is Set to a Secure Option (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  7.2 Ensure Passwords are Not Stored in the Global Configuration (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  7.3 Ensure Passwords are Set for All MySQL Accounts (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  7.4 Set 'default_password_lifetime' to Require a Yearly Password Change (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  7.5 Ensure Password Complexity Policies are in Place (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  7.6 Ensure No Users Have Wildcard Hostnames (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  7.7 Ensure No Anonymous Accounts Exist (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "8  Network"
# ---------------------------------------------------------------------------------------------------
echo "  8.1 Ensure 'require_secure_transport' is Set to 'ON' and/or 'have_ssl' is Set to 'YES' (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  8.2 Ensure 'ssl_type' is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  8.3 Set Maximum Connection Limits for Server and per User (Manual)"
echo "9  Replication"
echo "  9.1 Ensure Replication Traffic is Secured (Manual)"
# ---------------------------------------------------------------------------------------------------
echo "  9.2 Ensure 'SOURCE_SSL_VERIFY_SERVER_CERT' is Set to 'YES' or '1' (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  9.3 Ensure 'master_info_repository' is Set to 'TABLE' (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "  9.4 Ensure 'super_priv' is Not Set to 'Y' for Replication Users (Automated)"
# ---------------------------------------------------------------------------------------------------
echo "10  MySQL InnoDB Cluster / Group Replication"
echo "  10.1 Ensure All Group Replication Traffic is Secured (Manual)"
echo "  10.2 Allowlist Approved Servers Belonging to a MySQL InnoDB Cluster (Manual)"


