#!/usr/bin/env python3
'''
Purpose: Automate the creation of unique allowed HTTP and HTTPS destination lists per host based on prior activity.

Use:
  - Setup the rule variables in constants.py to match your environment
  - Run the library, e.g. 
    python3 -m detect.v2.create_host_connection_rule --protocol HTTP
    or 
    python3 -m detect.v2.create_host_connection_rule --protocol HTTPS

Notes:
  - If you have to delete a rule because it got messed up: python3 -m detect.v2.delete_rule --rule_id {rule_id}

'''
import time
import sys
import argparse
import pytz, datetime
from common import chronicle_auth
from . import create_rule
from . import create_rule_version
from . import run_retrohunt
from . import get_retrohunt
from . import list_detections
from . import constants

# Basic logger for output
import logging
logging.basicConfig(format='[*] %(asctime)s  -  %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p')


def re_make_rule(protocol, host_destination_pairs=None):
  '''
  Give a set of hosts and destiations to ignore, as well as pre-configured basic variables from constants.py

  Return a new rule with the updated host and destination pairs to ignore to create a new version
  '''
  
  applicable_subnet_list          = '\n              or '.join('net.ip_in_range_cidr($e1.principal.ip,"%s")' % x for x in constants.APPLICABLE_SUBNETS)
  APPLICABLE_SUBNETS_LINES = f'''          
        (
            {applicable_subnet_list}
        )
'''

  # Compile the ignored items, which will be an empty string if the array is null
  IGNORED_SUBNETS_LINES           = '\n'.join('        not net.ip_in_range_cidr($e1.principal.ip,"%s")' % x for x in constants.IGNORED_SUBNETS)
  IGNORED_DEST_HOST_SUBNETS_LINES = '\n'.join('        not net.ip_in_range_cidr($e1.target.ip,"%s")' % x for x in constants.IGNORED_DEST_HOST_SUBNETS)
  IGNORED_HOSTS_FOR_ALL_LINES     = '\n'.join('        not $e1.target.hostname = "%s"' % x for x in constants.IGNORED_HOSTS_FOR_ALL)

  # Add found destinations
  HOST_DESTINATION_PAIR_LINES = ""
  if host_destination_pairs:
    for host in sorted(host_destination_pairs.keys()):

      # Build the set of hosts to exclude, using wildcards as necessary
      destination_list_items = []
      for domain in sorted(host_destination_pairs[host]):
        if domain.startswith(".*."):
          destination_list_items.append(f're.regex($e1.target.hostname, "{domain}")')
        else:
          destination_list_items.append(f'$e1.target.hostname = "{domain}"')

      # Be sure desination items are unique from wildcard checks
      destination_list_items  = sorted(list(set(destination_list_items)))
      # Compile all of the host allow list destinations
      destination_list        = '\n                or '.join(destination_list_items)

      # Make the host exclusion
      if host.endswith(".*"):
        host_filter = f're.regex($e1.principal.hostname, "{host}")'
      else:
        host_filter = f'$e1.principal.hostname = "{host}"'

      # Add the new host filter
      HOST_DESTINATION_PAIR_LINES += f'''          
        not (
            {host_filter}
            and (
                {destination_list}
            )
        )
'''

  # Use the proper base protocol query type
  if protocol == "HTTP":
    BASE_PROTOCOL_QUERY = '''
        $e1.metadata.event_type = "NETWORK_HTTP"
        $e1.network.application_protocol = "HTTP"'''
  elif protocol == "HTTPS":
    BASE_PROTOCOL_QUERY = '''
        $e1.metadata.product_event_type = "bro_ssl"
        $e1.metadata.description = "SSL/TLS handshake info"'''

  # Creat the rule
  RULE = f'''rule {constants.RULE_NAME} {{
    meta:
        author = "{constants.RULE_AUTHOR}"
        description = "{constants.RULE_DESCRIPTION}"
        created = "{constants.CREATED_DATE}"
        severity = "{constants.SEVERITY}"
    events:
        re.regex($e1.principal.hostname, ".+")
        re.regex($e1.target.hostname, ".+")
        {BASE_PROTOCOL_QUERY}
{APPLICABLE_SUBNETS_LINES}
{IGNORED_SUBNETS_LINES}

{IGNORED_DEST_HOST_SUBNETS_LINES}

{IGNORED_HOSTS_FOR_ALL_LINES}

{HOST_DESTINATION_PAIR_LINES}
      condition:
          $e1
}}
'''

  return RULE


if __name__ == "__main__":
  ####################################################################################
  # Setup session
  ####################################################################################
  parser = argparse.ArgumentParser()
  chronicle_auth.add_argument_credentials_file(parser)
  # Add an argument to identify if you want to run HTTP or HTTPS
  parser.add_argument(
    "--protocol", type=str.upper, required=True, choices=["HTTP", "HTTPS"], help="Protocol (HTTP or HTTPS)")
  args = parser.parse_args()
  session = chronicle_auth.init_session(
      chronicle_auth.init_credentials(args.credentials_file))

  ####################################################################################
  # Create initial rule
  ####################################################################################
  # Get the initial rule text with base filters
  new_rule_text = re_make_rule(protocol=args.protocol)
  # Make the rule
  response = create_rule.create_rule(session, new_rule_text)
  rule_id = response['ruleId']
  version_id = response['versionId']
  logging.warning(f"Rule Created: {response}")


  ####################################################################################
  # Retrohunt and compile new additions to rule
  ####################################################################################
  # Base dictionary to use for compiling host-specific results into
  # You COULD replace this dictionary with prior results if you didn't want to start from scratch....
  detection_dict = {}
  while True:
    logging.warning("=======================================================================================")
    logging.warning("New retrohut")
    logging.warning("=======================================================================================")
    # Do an initial retrount on the rule, end time being enough back that you'll hvae data
    start_time = datetime.datetime.now(pytz.utc) - datetime.timedelta(days = constants.DAYS_TO_GO_BACK)
    end_time = datetime.datetime.now(pytz.utc) - datetime.timedelta(hours = 4)
    logging.warning(f"Searching between {start_time} and {end_time}")
    response = run_retrohunt.run_retrohunt(session, version_id, start_time, end_time)
    retrohunt_id = response['retrohuntId']

    # Reset something new being found for this set of results
    something_new_found = False
    # Compile the retrohunt results into the rule until nothing is found
    while True:
      # Get the retrohunt results
      response = get_retrohunt.get_retrohunt(session, version_id, retrohunt_id)

      # Wait for the results to be available
      if response['state'] == "DONE":
        # Iterate through the paginated results
        next_page_token = ""
        while True:
          logging.warning("Getting set of results")

          # Get  get the results
          detections = list_detections.list_detections(session, version_id, 1000, next_page_token, start_time, end_time, "")

          # For each detection, add it to the proper host/host prefix list
          for detection_event in detections[0]:
            # Some detections won't have a source hostname...skip them
            try:
              # Set the hostname to its matching prefix, if there is one.
              hostname = detection_event['collectionElements'][0]['references'][0]['event']['principal']['hostname']
              for host_prefix in constants.SOURCE_HOSTNAME_PREFIXES:
                if hostname.startswith(host_prefix):
                  hostname = f'{host_prefix}.*'
                  break

              # Check to see if destination is a wildcard item.  If so prefix with .*.
              destination = detection_event['collectionElements'][0]['references'][0]['event']['target']['hostname']
              for domain_to_wildcard in constants.DOMAINS_TO_WILDCARD:
                if destination.endswith(f".{domain_to_wildcard}") or destination == domain_to_wildcard:
                  destination = f".*.{domain_to_wildcard}"
                  break

              # Add the host if not already there
              if hostname not in detection_dict:
                detection_dict[hostname] = [destination]
                logging.warning(f"Adding host: {hostname} - Domain: {destination}")
                something_new_found = True
              # Add the destination if not already there
              else:
                if destination not in detection_dict[hostname]:
                  logging.warning(f"Adding host: {hostname} - Domain: {destination}")
                  detection_dict[hostname].append(destination)
                  something_new_found = True
            except Exception as e:
              logging.warning(f"Error on {detection_event} - {str(e)}")
          # Get next page token
          try:
            # If no next token, you're done with this set of results
            next_page_token = detections[1]
            if not next_page_token:
              break
            else:
              logging.warning(f"Pausing {constants.SLEEP_SEC_BETWEEN_PAGINATION} seconds before pulling the next page of results")       # avoids rate limit
              time.sleep(constants.SLEEP_SEC_BETWEEN_PAGINATION)
              continue
          # Handle another way to see if there is no next page token
          except:
            break 
        break
      else:
        logging.warning(f"Retrohunt not done yet.  Waiting {constants.SLEEP_SEC_WAITING_FOR_RETROHUNT} seconds")
        time.sleep(constants.SLEEP_SEC_WAITING_FOR_RETROHUNT)

    ####################################################################################
    # Re-Create Rule and Add New Version
    ####################################################################################
    if something_new_found:
      logging.warning("\nUpdating rule with new data...")
      logging.warning(f"Current allow list dict: {detection_dict}")

      # update the rule
      new_rule_content = re_make_rule(protocol=args.protocol, host_destination_pairs=detection_dict)
      version_id = create_rule_version.create_rule_version(session, rule_id, new_rule_content)
      logging.warning(f"New rule version_id created for next search: {version_id}")
      logging.warning(f"Waiting {constants.SLEEP_SEC_BETWEEN_LOOPS} seconds to be sure the new rule is applied\n")

      # Reset variable for next loop
      something_new_found = False

      time.sleep(constants.SLEEP_SEC_BETWEEN_LOOPS)
    else:
      logging.warning("Nothing new found this time.  WE'RE DONE!")
      break
