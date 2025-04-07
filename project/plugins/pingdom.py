import logging
import requests

from project import values


def pause_check(configMap, username, **key_args):

    PINGDOM_ACCOUNT_EMAIL = configMap["Global"]["pingdom"]["account_email"]
    API_KEY = configMap["Global"]["pingdom"]["api_key"]
    PINGDOM_USER = configMap["Global"]["pingdom"]["username"]
    PINGDOM_PSWD = configMap["Global"]["pingdom"]["password"]
    checks_to_pause = [key for key in key_args.keys() if not key.startswith("ad_")]
    if values.DryRun is True:
        logging.info(f"User {username}: Dry run of pause_check")
    else:

        for check in checks_to_pause:
            check_id = str(key_args.get(check))
            url = f"https://api.pingdom.com/api/2.1/checks/{check_id}?paused=true"
            response = requests.put(
                url,
                headers={"Account-Email": PINGDOM_ACCOUNT_EMAIL, "App-Key": API_KEY},
                auth=(PINGDOM_USER, PINGDOM_PSWD),
            )
            if response.status_code == 200:
                logging.info(f"User {username}: {check} paused")
            else:
                logging.error(f"User {username}: error pausing {check}")


def unpause_check(configMap, username, **key_args):

    PINGDOM_ACCOUNT_EMAIL = configMap["Global"]["pingdom"]["account_email"]
    API_KEY = configMap["Global"]["pingdom"]["api_key"]
    PINGDOM_USER = configMap["Global"]["pingdom"]["username"]
    PINGDOM_PSWD = configMap["Global"]["pingdom"]["password"]
    checks_to_unpause = [key for key in key_args.keys() if not key.startswith("ad_")]

    if values.DryRun is True:
        logging.info(f"User {username}: Dry run of unpause_check: ")
    else:
        for check in checks_to_unpause:
            check_id = str(key_args.get(check))
            url = f"https://api.pingdom.com/api/2.1/checks/{check_id}?paused=false"
            response = requests.put(
                url,
                headers={"Account-Email": PINGDOM_ACCOUNT_EMAIL, "App-Key": API_KEY},
                auth=(PINGDOM_USER, PINGDOM_PSWD),
            )
            if response.status_code == 200:
                logging.info(f"User {username}: {check} unpaused")
            else:
                logging.error(f"User {username}: error unpausing {check}")
