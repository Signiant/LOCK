import argparse
import importlib
import logging
import logging.handlers
import os
import sys
import yaml
from project.plugins import iam
from project.plugins.iam import validate_new_key, get_new_key, create_and_test_key, delete_older_key, get_iam_client
from project import values


def update_access_key(key):
    values.access_key = key


def set_DryRun(bool):
    values.DryRun = bool


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

    logFormatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
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
        key_args = {}
        # client = get_iam_client(configMap, **key_args)
        if username == 'all':
            for user_data in all_users:
                username = (next(iter(user_data)))
                iam.list_keys(configMap, username)
        else:
            iam.list_keys(configMap, username)

    elif args.action == 'rotate':  # run functions listed in the config file.
        if username == 'all':
            for user_data in all_users:
                username = (next(iter(user_data)))
                user_data = user_data.get(username)
                rotate_update(configMap, user_data, username, args.ssh_username, ssh_password)
        else:
            rotate_update(configMap, user_data, username, args.ssh_username, ssh_password)

    elif args.action == 'validate':  # validate that new key is being used and delete the old unused key
        if username == 'all':
            for userdata in all_users:
                username_to_validate = (next(iter(userdata)))
                user_data = userdata.get(username_to_validate)
                if user_data.get('plugins'):
                    if user_data.get('plugins')[0].get('iam'):
                        if 'get_new_key' in user_data.get('plugins')[0].get('iam')[0]:
                            validate_new_key(configMap, username_to_validate, user_data)
                        else:
                            logging.info(f'   No get_new_key section for iam plugin for user {username_to_validate} - skipping')
                    else:
                        logging.info(f'   No iam plugin section for user {username_to_validate} - skipping')
                else:
                    logging.info(f'   No plugins section for user {username_to_validate} - skipping')
        else:
            for userdata in all_users:
                username_to_validate = (next(iter(userdata)))
                if username == username_to_validate:
                    user_data = userdata.get(username_to_validate)
                    if user_data.get('plugins'):
                        if user_data.get('plugins')[0].get('iam'):
                            if 'get_new_key' in user_data.get('plugins')[0].get('iam')[0]:
                                validate_new_key(configMap, username_to_validate, user_data)
                            else:
                                logging.info(f'   No get_new_key section for iam plugin for user {username_to_validate} - skipping')
                        else:
                            logging.info(f'   No iam plugin section for user {username_to_validate} - skipping')
                    else:
                        logging.info(f'   No plugins section for user {username_to_validate} - skipping')


def rotate_update(config_map, user_data, username, ssh_username=None, ssh_password=None):
    update_access_key(('', ''))
    modules = user_data['plugins']
    try:
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
                    raise StopIteration
    except StopIteration:
        pass


if __name__ == "__main__":
    main()
