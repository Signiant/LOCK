import subprocess

from project import values


def run_command(configMap, username,  **key_args):

    from project.main import update_access_key

    list_of_commands = key_args.get('commands')
    for command in list_of_commands:
        command_run= command.replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>", values.access_key[1])
        command_run = command_run.split()
        print('command')

def print_instructions(configMap, username, **key_args):
    print(key_args.get('instructions'))