#!/usr/bin/env python3

######################################################################################################
# Variables to Update
######################################################################################################

# Days of historic traffic to look back on to create the rule. 
# Test with 1 to be sure you didn't miss any prefixes, live with ~30 once validated
DAYS_TO_GO_BACK     = 1

# Rule information
RULE_AUTHOR         = ""                   # Your name 
RULE_NAME           = ""                   # Name of the rule a-z, A-Z, 0-9, _   e.g. unexpected_http_outbound or unexpected_https_outbound
RULE_DESCRIPTION    = ""                   # e.g. "Unespected HTTP Outbound" or "Unespected HTTPS Outbound"
CREATED_DATE        = ""                   # Current date
SEVERITY            = "Critical"           # Critical, High, Medium, Low

# Subnets to alert on
APPLICABLE_SUBNETS          = [ "10.0.0.0/8", ]              # Subnets for hosts you want to alert on
IGNORED_SUBNETS             = [ ]                            # Source subnets you don't want incldued, e.g. VPC peered subnets with zeek logs in Chronicle
IGNORED_DEST_HOST_SUBNETS   = [ "10.0.0.0/8", "169.254.169.254/32" ]       # Destination subnets to ignore, e.g. internal<=> internal + metadata server

# Example hosts to ignore
IGNORED_HOSTS_FOR_ALL = [
    "metadata.google.internal", 
    "archive.canonical.com",
    "ppa.launchpad.net",
]

# Some domains will have a TON of subdomains.  
# For those domains, allow instances to go out to a wildcard version of it
DOMAINS_TO_WILDCARD = [
    "debian.org",
    "googleusercontent.com",
    "ubuntu.com",
]

# Hostname prefix examples
SOURCE_HOSTNAME_PREFIXES = [
    "gke",
    "jump",
    "mysql",
    "nginx",
]


######################################################################################################
# Variables to leave alone
######################################################################################################
SLEEP_SEC_BETWEEN_LOOPS             = 30
SLEEP_SEC_BETWEEN_PAGINATION        = 30
SLEEP_SEC_WAITING_FOR_RETROHUNT     = 10
