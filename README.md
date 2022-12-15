# CIS Benchmark MySQL/MariaDB compliance script

## What to expect

* Intended version is : "CIS Benchmark MySQL Entreprise Edition 8.0 Benchmark v1.2.0"

Targeted database engine is **MariaDB** so some adjustements are needed for MySQL, you can directly refers to CIS documentation to have full audit and remediation commands.

Consider this script as a helper in fulfilling CIS requirements, some test and remediation may be missing

Edit constants in script top part according to your system.
WARNING : use 'REMEDIATION="YES"' at your own risk as it can mess up your current configuration, in addition automatic remediation must not be used while in production

## Why this repo ?

Getting tired of manually check SQL CIS compliances. In addition, CIS guide is designed for MySQL and not MariaDB but can be adapted for most of it.

