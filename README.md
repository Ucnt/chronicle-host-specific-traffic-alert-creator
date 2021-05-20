# Chronicle GCP Host Specific Traffic Alert Creator

## Purpose
This script creates host specific unexpected traffic alerts in Chronicle based on historic Zeek HTTP and HTTPS (SSL) logs.

## Chronicle Blog Post
Chronicle has a [blog post, link to be updated when live](https://chroniclesec.medium.com/) discussing the below problem statement and solution.

## Background
If you are sending Zeek HTTP and HTTPS (SSL) logs to Chronicle and have setup [DHCP Correlation with Chronicle](https://github.com/Ucnt/chronicle-gcp-dhcp-log-creator), the next step is to create alerts on the traffic.  

One of the primary alerts is when a host or host type reaches out to a domain that you weren't expecting, e.g. a compromised system, someone loading unapproved software, or one of many system changes that affect traffic.

To do this, you can (through these scripts) create a list of known and approved domains that can be accessed and alert on access outside of that approved list.

## Methodology

- For the given protocol (HTTP or HTTPS)
  - Create a base Chronicle rule with your subnet and ignored host configuration.
  - While True (infinite loop)
    - Run a historic search on the base rule
    - If there are results
      - Add accessed domains to a per-GCP host list.
      - Update the Chronicle rule with the hew host lists
      - Continue with the loop
    - Else, end.


## Setup/Prerequisites
1. Read through the [blog post, link to be updated when live](https://chroniclesec.medium.com/), to understand the methodology
2. Be a [Chronicle Security](https://chronicle.security/) customer with Zeek HTTP + HTTPS (SSL) logs
3. Setup DHCP correlation with Chronicle through [these scripts](https://github.com/Ucnt/chronicle-gcp-dhcp-log-creator) or some other method
4. Download and setup [Chronicle's api-samples-python repository](https://github.com/chronicle/api-samples-python)
5. Clone this repo
6. Adjust the constants.py file in this repo to align with your requirements
7. Copy the .py files from this repo into the api-samples-python repository's detect/v2 folder

## Execution

These steps follow the recommendation to initially look back 1 day in order to validate that you have setup your DOMAINS_TO_WILDCARD and SOURCE_HOSTNAME_PREFIXES variables correctly (i.e. you didn't miss a GKE workload that has dozens of instances or a domain for which you access numerous subdomains).

1. Go to the base api-samples-python repository folder.

2. Ensure that your constants.py file DAYS_TO_GO_BACK variable is set to 1

3. To create your test HTTP rule, run: 

   ```
   python3 -m detect.v2.create_host_connection_rule --protocol HTTP
   ```

4. To create your test HTTPS (SSL) rule, run: 

   ```
   python3 -m detect.v2.create_host_connection_rule --protocol HTTPS
   ``` 

5. Once the rules look correct, delete both of them by running a command like below for each:

   ```
   python3 -m detect.v2.delete_rule --rule_id {Rule id of the above rules, e.g. ru_12345678-1234-1234-1234-123456789012}
   ``` 

6. Update the constants.py file DAYS_TO_GO_BACK variable to 30 (recommended value)

7. Re-run steps 3 and 4.


## Post-Execution Steps

   * For each rule, check through the domains for each host and validate that those domains are approved.

   * If any domains are NOT approved, investigate + remediate the issue and remove the domain from the rule.

   * Make the Chronicle rule live and enable alerting (if desired)