from project import values

import logging
import requests

CHECKS_URL = "https://api.pingdom.com/api/3.1/checks"


def set_checks_paused(config_map, username, paused, **key_args):
    api_key = config_map["Global"]["pingdom"]["api_key"]
    action, acting = ("pause", "pausing") if paused else ("unpause", "unpausing")
    # Each check is a display name mapped to its numeric Pingdom check ID
    checks = {
        name: check_id for name, check_id in key_args.items() if type(check_id) is int
    }

    if values.DryRun is True:
        logging.info(f"User {username}: Dry run of {action}_check")
        return

    for check, check_id in checks.items():
        response = requests.put(
            f"{CHECKS_URL}/{check_id}",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"paused": paused},
            timeout=30,
        )
        if response.status_code == 200:
            logging.info(f"User {username}: {check} {action}d")
        else:
            logging.error(
                f"User {username}: error {acting} {check} "
                f"(HTTP {response.status_code}): {response.text}"
            )


def pause_check(config_map, username, **key_args):
    set_checks_paused(config_map, username, True, **key_args)


def unpause_check(config_map, username, **key_args):
    set_checks_paused(config_map, username, False, **key_args)
