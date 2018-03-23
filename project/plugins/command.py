import subprocess

import os

from project import values
from subprocess import call


def run_command(configMap, username,  **key_args):

    list_of_commands = key_args.get('commands')
    for command in list_of_commands:
        command = command.replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>", values.access_key[1])
        command = command.split()
        call(command)


def print_instructions(configMap, username, **key_args):
    print(key_args.get('instructions'))


# def set_environment_key(configMap, username,  **key_args):
#     os.environ["AWS_ACCESS_KEY_ID"] = values.access_key[0]
#     os.environ["AWS_SECRET_ACCESS_KEY"] = values.access_key[1]


def set_environment_variables(configMap, username,  **key_args):
    for var in key_args.get('variables'):
        pair = var.split('=')
        os.environ[pair[0]] = pair[1]


