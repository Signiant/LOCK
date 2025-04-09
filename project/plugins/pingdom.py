from project import values

import logging
import requests


def pause_check(config_map, username, **key_args):
    pingdom_account_email = config_map["Global"]["pingdom"]["account_email"]
    api_key = config_map["Global"]["pingdom"]["api_key"]
    pingdom_user = config_map["Global"]["pingdom"]["username"]
    pingdom_pswd = config_map["Global"]["pingdom"]["password"]
    checks_to_pause = [key for key in key_args.keys() if not key.startswith("ad_")]
    if values.DryRun is True:
        logging.info(f"User {username}: Dry run of pause_check")
    else:

        for check in checks_to_pause:
            check_id = str(key_args.get(check))
            url = f"https://api.pingdom.com/api/2.1/checks/{check_id}?paused=true"
            response = requests.put(
                url,
                headers={"Account-Email": pingdom_account_email, "App-Key": api_key},
                auth=(pingdom_user, pingdom_pswd),
            )
            if response.status_code == 200:
                logging.info(f"User {username}: {check} paused")
            else:
                logging.error(f"User {username}: error pausing {check}")


def unpause_check(config_map, username, **key_args):

    pingdom_account_email = config_map["Global"]["pingdom"]["account_email"]
    api_key = config_map["Global"]["pingdom"]["api_key"]
    pingdom_user = config_map["Global"]["pingdom"]["username"]
    pingdom_pswd = config_map["Global"]["pingdom"]["password"]
    checks_to_unpause = [key for key in key_args.keys() if not key.startswith("ad_")]

    if values.DryRun is True:
        logging.info(f"User {username}: Dry run of unpause_check: ")
    else:
        for check in checks_to_unpause:
            check_id = str(key_args.get(check))
            url = f"https://api.pingdom.com/api/2.1/checks/{check_id}?paused=false"
            response = requests.put(
                url,
                headers={"Account-Email": pingdom_account_email, "App-Key": api_key},
                auth=(pingdom_user, pingdom_pswd),
            )
            if response.status_code == 200:
                logging.info(f"User {username}: {check} unpaused")
            else:
                logging.error(f"User {username}: error unpausing {check}")
