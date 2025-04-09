from project import values
from subprocess import call

import logging
import os


def run_command(_, username, **key_args):
    list_of_commands = key_args.get("commands")
    for command in list_of_commands:
        command = command.replace(
            "<new_key_name>", values.access_keys[username][0]
        ).replace("<new_key_secret>", values.access_keys[username][1])
        command = command.split()

        if values.DryRun is True:
            logging.info(f"User {username}: Dry run of command:" + command)
        else:
            call(command)


def set_environment_variables(_, __, **key_args):
    for var in key_args.get("variables"):
        pair = var.split("=")
        os.environ[pair[0]] = pair[1]


def print_instructions(_, username, **key_args):
    logging.info(f"User {username}: {key_args.get('instructions')}")
