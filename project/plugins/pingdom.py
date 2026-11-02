from project import values

import logging
import requests

CHECKS_URL = "https://api.pingdom.com/api/3.1/checks"


def set_checks_paused(config_map, username, paused, **key_args):
    api_key = config_map["Global"]["pingdom"]["api_key"]
    action = "pause" if paused else "unpause"
    checks = [key for key in key_args.keys() if not key.startswith("ad_")]

    if values.DryRun is True:
        logging.info(f"User {username}: Dry run of {action}_check")
        return

    for check in checks:
        check_id = str(key_args.get(check))
        response = requests.put(
            f"{CHECKS_URL}/{check_id}",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"paused": paused},
        )
        if response.status_code == 200:
            logging.info(f"User {username}: {check} {action}d")
        else:
            logging.error(
                f"User {username}: error {action}ing {check} "
                f"(HTTP {response.status_code}): {response.text}"
            )


def pause_check(config_map, username, **key_args):
    set_checks_paused(config_map, username, True, **key_args)


def unpause_check(config_map, username, **key_args):
    set_checks_paused(config_map, username, False, **key_args)
