import logging
import os
from project import values
from subprocess import call


def run_command(configMap, username,  **key_args):

    list_of_commands = key_args.get('commands')
    for command in list_of_commands:
        command = command.replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>", values.access_key[1])
        command = command.split()

        if values.DryRun is True:
            logging.info(f'User {username}: Dry run of command:' + command)
        else:
            call(command)

def set_environment_variables(configMap, username,  **key_args):
    for var in key_args.get('variables'):
        pair = var.split('=')
        os.environ[pair[0]] = pair[1]


def print_instructions(configMap, username, **key_args):
   logging.info(f"User {username}: {key_args.get('instructions')}")