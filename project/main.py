#!/usr/bin/env python3

from pathlib import Path

LOCK_root = str(Path(__file__).resolve().parent.parent)
print(f"Project is running from: {LOCK_root}")

import sys

sys.path.append(LOCK_root)

from project.plugins import iam
from project.plugins.iam import validate_new_key, delete_old_key
from project import values
from project import utils

import argparse
import importlib
import logging
import logging.handlers
import os
import re
import sys
import yaml
import requests


def resolve_target_users(all_users, usernames):
    if usernames == "all":
        return all_users
    if isinstance(usernames, str):
        usernames = [usernames]
    return [u for u in all_users if next(iter(u)) in usernames]


def validate_keys_for_user(userdata, config_map, keys_to_delete):
    username_to_validate = next(iter(userdata))
    user_data = userdata.get(username_to_validate)
    if user_data.get("plugins"):
        iam_plugin = user_data.get("plugins")[0].get("iam")
        if iam_plugin:
            if (
                "get_new_key" in iam_plugin[0]
                or "rotate_ses_smtp_user" in iam_plugin[0]
            ):
                validation_result = validate_new_key(
                    config_map, username_to_validate, user_data
                )
                if validation_result is not None:
                    old_key, prompt = validation_result
                    keys_to_delete.append((username_to_validate, old_key, prompt))
            else:
                logging.info(
                    f"   No get_new_key or rotate_ses_smtp_user section for iam plugin for user {username_to_validate} - skipping"
                )
        else:
            logging.info(
                f"   No iam plugin section for user {username_to_validate} - skipping"
            )
    else:
        logging.info(
            f"   No plugins section for user {username_to_validate} - skipping"
        )


def validate_keys(usernames, all_users, config_map):
    keys_to_delete = []
    target_users = resolve_target_users(all_users, usernames)
    for user_data in target_users:
        validate_keys_for_user(user_data, config_map, keys_to_delete)
    for owner, key, prompt in keys_to_delete:
        user_data = [data for data in all_users if next(iter(data)) == owner][0][owner]
        delete_old_key(user_data, config_map, owner, key, prompt)


def rotate_update(user_data, config_map, ssh_username=None, ssh_password=None):
    username = next(iter(user_data))
    modules = user_data[username]["plugins"]

    update_access_key(username, ("", ""))

    for plugin in modules:
        my_plugin = importlib.import_module("project.plugins." + list(plugin.keys())[0])
        plugin = plugin.get(list(plugin.keys())[0])
        for method in plugin:  # modules = dict, module = str
            key_args = method[list(method.keys())[0]]  # get key pair of method to run
            if key_args is None:
                key_args = {}
            if ssh_username:
                key_args["ssh_user"] = ssh_username
            if ssh_password:
                key_args["ssh_password"] = ssh_password
            method_to_call = getattr(
                my_plugin, list(method.keys())[0]
            )  # get method name to run
            logging.info(
                f"User {username}: Running "
                + str(method_to_call)[:-15].lstrip("<")
                + "for "
                + username
            )
            result = method_to_call(config_map, username, **key_args)
            # TODO: Check result and abort remaining methods if one fails
            if "get_new_key" in str(method_to_call) and not result:
                logging.error(f"Failed to get new key - skipping {username}")
                return


def rotate_keys(usernames, all_users, config_map, ssh_username, ssh_password):
    target_users = resolve_target_users(all_users, usernames)
    utils.run_threads(
        target_users, rotate_update, config_map, ssh_username, ssh_password
    )


def list_keys_for_user(user_data, config_map):
    username = next(iter(user_data))
    iam.list_keys(config_map, username)


def list_keys(usernames, all_users, config_map):
    target_users = resolve_target_users(all_users, usernames)
    utils.run_threads(target_users, list_keys_for_user, config_map)


def update_access_key(username, key):
    values.access_keys[username] = key


def set_dry_run(dry_run):
    values.DryRun = dry_run


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


def verify_public_ip(required_public_ip):
    if required_public_ip is False:
        logging.info("Skipping public IP verification.")
    else:
        if required_public_ip.lower() == "false":
            logging.info("Skipping public IP verification.")
        else:
            logging.info(
                f"Checking if current public IP is {required_public_ip} (either in the office or on VPN)"
            )
            myip = requests.get("https://api.ipify.org").text
            if myip == required_public_ip:
                logging.info(
                    f"Verified public IP address is: {myip} - LOCK will continue"
                )
            else:
                logging.error(
                    f"Incorrect public IP detected ({myip}) - LOCK cannot continue"
                )
                sys.exit(1)


def read_config_file(path):
    try:
        logging.debug(f"Config file path {path}")
        config_file_handle = open(path)
        config_map = yaml.load(config_file_handle, Loader=yaml.FullLoader)
        config_file_handle.close()
    except Exception as e:
        logging.error(
            f"Error: Unable to open config file {path} or invalid Yaml {str(e)}"
        )
        sys.exit(1)
    return config_map


def main():

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    parser = argparse.ArgumentParser(
        description="LOCK Let's Occasionally Circulate Keys"
    )
    parser.add_argument(
        "-u",
        "--users",
        help="aws user to rotate, or a comma-separated list of users",
        required=False,
    )
    parser.add_argument(
        "-c", "--config", help="Full path to a config file", required=True
    )
    parser.add_argument(
        "-a",
        "--action",
        help="Select the action to run: keys, rotate, validate",
        required=False,
    )
    parser.add_argument(
        "-k",
        "--key",
        help="Manually enter new key by skipping get_new_key method",
        required=False,
    )
    parser.add_argument(
        "-i", "--instance", help="The instance to act on.", required=False
    )
    parser.add_argument(
        "-d",
        "--dryRun",
        help="Run without creating keys or updating keys",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "-p", "--profile", help="The name of the AWS credential profile", required=False
    )
    parser.add_argument(
        "-z",
        "--hidekey",
        help="Only display access key id when creating a key",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "-e",
        "--debug",
        help="Set logging level to debug",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--ssh_username",
        help="Username for SSH (if required)",
        default=None,
        required=False,
    )
    parser.add_argument(
        "--ssh_password",
        help="Password for SSH (if required)",
        default=None,
        required=False,
    )
    args = parser.parse_args()

    log_level = logging.INFO
    if args.debug:
        print("DEBUG logging requested")
        log_level = logging.DEBUG

    log_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s: (tid=%(thread)d) [%(module)s] %(message)s"
    )
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(log_formatter)
    file_handler = logging.FileHandler("lock.log")
    file_handler.setFormatter(log_formatter)
    file_handler.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    config_map = read_config_file(args.config)

    if "RequiredParameters" in config_map:
        missing_parameters = verify_parameters_set(config_map["RequiredParameters"])
        if len(missing_parameters) > 0:
            logging.error(
                f"Required parameters are missing:\n{yaml.safe_dump(missing_parameters, indent=4)}"
            )
            sys.exit(1)

        if config_map["RequiredParameters"].get("env"):
            export_environment_variables(**config_map["RequiredParameters"]["env"])

    public_ip_required = os.getenv("PUBLIC_IP_REQUIRED", False)
    verify_public_ip(public_ip_required)

    # args.dryRun = True
    if args.users:
        usernames = [u.strip() for u in args.users.split(",") if u.strip()]
        if usernames == ["all"]:
            usernames = "all"
    else:
        usernames = "test_lock"
    if args.action is None:
        args.action = "list"  # 'instance:status'

    set_dry_run(args.dryRun)
    values.hide_key = args.hidekey

    if args.dryRun is True:
        logging.info("Dry Run")

    if args.profile is not None:
        values.profile = args.profile

    ssh_password = args.ssh_password
    if args.ssh_username:
        if not args.ssh_password:
            ssh_password = input(f"Password for {args.ssh_username}: ")

    logging.debug(f"Config file {str(config_map)}")
    all_users = config_map["Users"]

    if usernames != "all":
        requested = usernames if isinstance(usernames, list) else [usernames]
        all_usernames = {next(iter(u)) for u in all_users}
        missing = [u for u in requested if u not in all_usernames]
        if missing:
            logging.info(f"{', '.join(missing)} does not exist in the config file.")
            sys.exit()

    # get manually entered key, if any
    if args.key is not None:
        if isinstance(usernames, list) and len(usernames) != 1:
            logging.error("-k/--key can only be used with a single user.")
            sys.exit(1)
        key_username = usernames[0] if isinstance(usernames, list) else usernames
        update_access_key(key_username, args.key)

    if args.action == "list":
        list_keys(usernames, all_users, config_map)
    elif args.action == "rotate":  # run functions listed in the config file.
        rotate_keys(usernames, all_users, config_map, args.ssh_username, ssh_password)
    elif (
        args.action == "validate"
    ):  # validate that new key is being used and delete the old unused key
        validate_keys(usernames, all_users, config_map)


if __name__ == "__main__":
    main()
