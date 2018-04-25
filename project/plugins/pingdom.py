import logging
import requests

from project import values


def pause_check(configMap, username,  **key_args):

    PINGDOM_ACCOUNT_EMAIL = configMap['Global']['pingdom']['account_email']
    API_KEY = configMap['Global']['pingdom']['api_key']
    PINGDOM_USER = configMap['Global']['pingdom']['username']
    PINGDOM_PSWD = configMap['Global']['pingdom']['password']
    checks_to_pause = list(key_args.keys())
    if values.DryRun is True:
        logging.info('Dry run of pause_check')
    else:

        for check in checks_to_pause:
            url = "https://api.pingdom.com/api/2.1/checks/<checkid>?paused=true".replace('<checkid>', str(key_args.get(check)))
            response = requests.put(url,  headers={'Account-Email': PINGDOM_ACCOUNT_EMAIL, 'App-Key': API_KEY}, auth=(PINGDOM_USER, PINGDOM_PSWD))
            if response.status_code == 200:
                logging.info("    %s paused" % check)
            else:
                logging.error("    error pausing %s " % check)


def unpause_check(configMap, username,  **key_args):

    PINGDOM_ACCOUNT_EMAIL = configMap['Global']['pingdom']['account_email']
    API_KEY = configMap['Global']['pingdom']['api_key']
    PINGDOM_USER = configMap['Global']['pingdom']['username']
    PINGDOM_PSWD = configMap['Global']['pingdom']['password']
    checks_to_unpause = list(key_args.keys())

    if values.DryRun is True:
        logging.info('Dry run of unpause_check: ')
    else:
        for check in checks_to_unpause:
            url = "https://api.pingdom.com/api/2.1/checks/<checkid>?paused=false".replace('<checkid>', str(key_args.get(check)))
            response = requests.put(url, headers={'Account-Email': PINGDOM_ACCOUNT_EMAIL, 'App-Key': API_KEY},
                                auth=(PINGDOM_USER, PINGDOM_PSWD))
            if response.status_code == 200:
                logging.info("    %s unpaused" % check)
            else:
                logging.error("    error unpausing %s " % check)
