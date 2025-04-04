#!/usr/bin/env python3

from pathlib import Path
LOCK_root = str(Path(__file__).resolve().parent.parent)
print(f"Project is running from: [{LOCK_root}]")

import sys
sys.path.append(LOCK_root)

import argparse
import importlib
import logging
import logging.handlers
import os
import re
import subprocess
import sys
import yaml
from project.plugins import iam
from project.plugins.iam import validate_new_key, delete_old_key
from project import values
from project import utils


def validate_keys_for_user(userdata, configMap, username, keys_to_delete):
    username_to_validate = (next(iter(userdata)))
    if username != "all" and username != username_to_validate:
        return
    user_data = userdata.get(username_to_validate)
    if user_data.get('plugins'):
        if user_data.get('plugins')[0].get('iam'):
            if 'get_new_key' in user_data.get('plugins')[0].get('iam')[0]:
                validation_result = validate_new_key(configMap, username_to_validate, user_data)
                if validation_result is not None:
                    old_key, prompt = validation_result
                    keys_to_delete.append((username_to_validate, old_key, prompt))
            else:
                logging.info(
                    f'   No get_new_key section for iam plugin for user {username_to_validate} - skipping')
        else:
            logging.info(f'   No iam plugin section for user {username_to_validate} - skipping')
    else:
        logging.info(f'   No plugins section for user {username_to_validate} - skipping')


def validate_keys(username, all_users, configMap):
    keys_to_delete = []
    utils.run_threads(all_users, validate_keys_for_user, configMap, username, keys_to_delete)
    for owner, key, prompt in keys_to_delete:
        user_data = [data for data in all_users if next(iter(data)) == owner][0][owner]
        delete_old_key(user_data, configMap, owner, key, prompt)


def rotate_update(user_data, config_map, username=None, ssh_username=None, ssh_password=None):
    update_access_key(('', ''))
    if username is None:
        username = (next(iter(user_data)))
        modules = user_data[username]['plugins']
    else:
        modules = user_data['plugins']
    for plugin in modules:
        my_plugin = importlib.import_module('project.plugins.' + list(plugin.keys())[0])
        plugin = plugin.get(list(plugin.keys())[0])
        for method in plugin:  # modules = dict, module = str
            key_args = (method[list(method.keys())[0]])  # get key pair of method to run
            if key_args is None:
                key_args = {}
            if ssh_username:
                key_args['ssh_user'] = ssh_username
            if ssh_password:
                key_args['ssh_password'] = ssh_password
            method_to_call = getattr(my_plugin, list(method.keys())[0])  # get method name to run
            logging.info("Running "+str(method_to_call)[:-15].lstrip('<') + "for " + username)
            result = method_to_call(config_map, username, **key_args)
            # TODO: Check result and abort remaining methods if one fails
            if 'get_new_key' in str(method_to_call) and not result:
                logging.error(f'Failed to get new key - skipping {username}')
                return


def rotate_keys(username, all_users, configMap, user_data, ssh_username, ssh_password):
    if username == 'all':
        utils.run_threads(all_users, rotate_update, configMap, None, ssh_username, ssh_password)
    else:
        rotate_update(user_data, configMap, username, ssh_username, ssh_password)


def list_keys_for_user(user_data, configMap):
    username = (next(iter(user_data)))
    iam.list_keys(configMap, username)


def list_keys(username, all_users, configMap):
    if username == 'all':
        utils.run_threads(all_users, list_keys_for_user, configMap)
    else:
        iam.list_keys(configMap, username)


def update_access_key(key):
    # TODO I need to make sure nothing breaks as each thread is currently accessing values.access_key.
    #  This variable is currently only modified in this function.
    values.access_key = key


def set_DryRun(bool):
    values.DryRun = bool


def check_for_placeholders(group_name, group):
    if group_name == "env":
        placeholders = {}
        for name, value in group.items():
            if type(value) is list:
                if type(value) is str and re.match("<.*>", value):
                    if name not in placeholders:
                        placeholders[name] = []
                    placeholders[name].append(value)
            else:
                if type(value) is str and re.match("<.*>", value):
                    placeholders[name] = value
    else:
        placeholders = []
        for value in group:
            if type(value) is str and re.match("<.*>", value):
                placeholders.append(value)
    return placeholders


def verify_parameters_set(required_parameters):
    missing_parameters = {}
    for group_name, group in required_parameters.items():
        placeholders = check_for_placeholders(group_name, group)
        if len(placeholders) > 0:
            missing_parameters[group_name] = placeholders
    return missing_parameters


def export_environment_variables(**kwargs):
    for name, value in kwargs.items():
        os.environ[name] = str(value)


def verify_vpn_enabled():
    logging.info("Checking if connected to VPN...")
    response = subprocess.run(["ifconfig", "ppp0"], capture_output=True, text=True)
    code = response.returncode
    if code != 0:
        logging.error("Please confirm that you are connected to the VPN.")
        sys.exit(1)
    else:
        logging.info("User is connected to VPN (interface ppp0). LOCK will continue.")


def readConfigFile(path):
    try:
        logging.debug(f"Config file path {path}")
        config_file_handle = open(path)
        configMap = yaml.load(config_file_handle, Loader=yaml.FullLoader)
        config_file_handle.close()
    except Exception as e:
        logging.error(f"Error: Unable to open config file {path} or invalid Yaml {str(e)}")
        sys.exit(1)
    return configMap


def main():

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    parser = argparse.ArgumentParser(description='LOCK Let\'s Occasionally Circulate Keys')
    parser.add_argument('-u', '--user', help='aws user to rotate', required=False)
    parser.add_argument('-c', '--config', help='Full path to a config file', required=True)
    parser.add_argument('-a', '--action', help='Select the action to run: keys, rotate, validate', required=False)
    parser.add_argument('-k', '--key', help='Manually enter new key by skipping get_new_key method', required=False)
    parser.add_argument('-i', '--instance', help='The instance to act on.', required=False)
    parser.add_argument('-d', '--dryRun', help='Run without creating keys or updating keys', action='store_true', required=False)
    parser.add_argument('-p', '--profile', help='The name of the AWS credential profile', required=False)
    parser.add_argument('-z', '--hidekey', help='Only display access key id when creating a key', action='store_true', required=False)
    parser.add_argument('-e', '--debug', help='Set logging level to debug', action='store_true', required=False)
    parser.add_argument('--ssh_username', help='Username for SSH (if required)', default=None, required=False)
    parser.add_argument('--ssh_password', help='Password for SSH (if required)', default=None, required=False)
    args = parser.parse_args()

    log_level = logging.INFO
    if args.debug:
        print('DEBUG logging requested')
        log_level = logging.DEBUG

    logFormatter = logging.Formatter('%(asctime)s - %(levelname)s: (tid=%(thread)d) [%(module)s] %(message)s')
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.DEBUG)
    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(log_level)
    consoleHandler.setFormatter(logFormatter)
    fileHandler = logging.FileHandler("lock.log")
    fileHandler.setFormatter(logFormatter)
    fileHandler.setLevel(logging.DEBUG)
    rootLogger.addHandler(fileHandler)
    rootLogger.addHandler(consoleHandler)

    configMap = readConfigFile(args.config)

    if "RequiredParameters" in configMap:
        missing_parameters = verify_parameters_set(configMap["RequiredParameters"])
        if len(missing_parameters) > 0:
            logging.error(f"Required parameters are missing:\n{yaml.safe_dump(missing_parameters, indent=4)}")
            sys.exit(1)

        if configMap["RequiredParameters"].get("env"):
            export_environment_variables(**configMap["RequiredParameters"]["env"])

    if os.getenv("VPN_REQUIRED", "False").lower() == "true":
        verify_vpn_enabled()

    # args.dryRun = True
    username = args.user
    if args.user is None:
        username = 'test_lock'  # args.user
    if args.action is None:
        args.action = 'list'  # 'instance:status'

    set_DryRun(args.dryRun)
    values.hide_key = args.hidekey

    if args.dryRun is True:
        logging.info("Dry Run")

    if args.profile is not None:
        values.profile = args.profile

    ssh_password = args.ssh_password
    if args.ssh_username:
        if not args.ssh_password:
            ssh_password = input(f"Password for {args.ssh_username}: ")

    logging.debug(f"Config file {str(configMap)}")
    user_data = None
    all_users = configMap['Users']
    for userdata in all_users:
        if username == (next(iter(userdata))):
            user_data = userdata.get(username)

    if 'user_data' not in locals() and username != 'all':
        logging.info(username+' does not exist in the config file.')
        sys.exit()

    # get manually entered key, if any
    if args.key is not None:
        update_access_key(args.key)

    if args.action == 'list':
        list_keys(username, all_users, configMap)
    elif args.action == 'rotate':  # run functions listed in the config file.
        rotate_keys(username, all_users, configMap, user_data, args.ssh_username, ssh_password)
    elif args.action == 'validate':  # validate that new key is being used and delete the old unused key
        validate_keys(username, all_users, configMap)


if __name__ == "__main__":
    main()
