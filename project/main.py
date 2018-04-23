import argparse
import importlib
import logging
import logging.handlers
import os
import sys
import yaml
from project.plugins import iam
from project.plugins.iam import validate_new_key, get_new_key, create_and_test_key, delete_older_key, get_iam_client
from project.plugins.ec2 import list_instances, get_instance_status,  terminate_instance_id
from project import values


def update_access_key(key):
    values.access_key = key

def set_DryRun(bool):
    values.DryRun = bool

def readConfigFile(path):
    configMap = []
    try:
        config_file_handle = open(path)
        configMap = yaml.load(config_file_handle)
        config_file_handle.close()
    except:
        logging.critical("Error: Unable to open config file %s or invalid Yaml" % path)
    return configMap


def main():

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    parser = argparse.ArgumentParser(description='LOCK Let\'s Occasionally Circulate Keys')
    parser.add_argument('-u', '--user', help='aws user to rotate', required=False)
    parser.add_argument('-c', '--config', help='Full path to a config file', required=True)
    parser.add_argument('-a', '--action', help='Select the action to run: keys, rotate, validate', required=False)
    parser.add_argument('-k', '--key', help='Manually enter new key by skipping get_new_key method', required=False)
    parser.add_argument('-i', '--instance', help='The instance to act on.',required=False)
    parser.add_argument('-d', '--dryRun', help='Run without creating keys or updating keys', action='store_true' ,required=False)
    parser.add_argument('-p', '--profile', help='The name of the AWS credential profile',required=False)
    parser.add_argument('-z', '--hidekey', help='Only display access key id when creating a key', action='store_true' ,required=False)
    parser.add_argument('-e', '--debug', help='Set logging level to debug', action='store_true' ,required=False)
    args = parser.parse_args()
    configMap = readConfigFile(args.config)

    logFormatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.INFO)
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    if args.debug:
        consoleHandler.setLevel(logging.DEBUG)
    else:
        consoleHandler.setLevel(logging.INFO)
    fileHandler = logging.FileHandler("lock.log")
    fileHandler.setFormatter(logFormatter)
    fileHandler.setLevel(logging.ERROR)
    rootLogger.addHandler(fileHandler)
    rootLogger.addHandler(consoleHandler)

    args.dryRun = True
    username=args.user
    if args.user is None:
        username = 'test_lock'  # args.user
    if args.action is None:
        args.action = 'list'  # 'instance:status'


    set_DryRun(args.dryRun)
    values.hide_key = args.hidekey

    if args.dryRun is True:
        logging.critical("Dry Run")

    if args.profile is not None:
        values.profile = args.profile

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
        key_args={}
        client = get_iam_client(configMap, **key_args )
        if username == 'all':
            for user_data in all_users:
                username = (next(iter(user_data)))
                iam.list_keys(configMap, username, client)
        else:
            iam.list_keys(configMap, username, client)

    elif args.action == 'rotate':  # run functions listed in the config file.
        if username == 'all':
            for user_data in all_users:
                username = (next(iter(user_data)))
                user_data = user_data.get(username)
                rotate_update(configMap, user_data, username)
        else:
            rotate_update(configMap, user_data, username)

    elif args.action == 'validate':  # validate that new key is being used and delete the old unused key
        if username == 'all':
            for user_data in all_users:
                username = (next(iter(user_data)))
                validate_new_key(configMap, username)
        else:
            validate_new_key(configMap, username)

    elif args.action == 'getnewkey':  # if you only want to
        get_new_key(configMap, username)

    elif args.action == 'instance:ids':
        instances = user_data['instances']
        list_instances(configMap, instances)

    elif args.action == 'instance:terminate':
        if args.instance is not None:
            key_args = {'instance_id': args.instance}
            terminate_instance_id(configMap, **key_args)
        else:
            logging.critical("Provide an instance id. '-i x'")

    elif args.action == 'instance:status':
        if args.instance is not None:
            key_args = {'instance_id': args.instance}
            get_instance_status(configMap, **key_args)
        else:
            logging.critical("Provide an instance id. '-i x' ")

    print("")


def rotate_update(configMap, user_data, username):
    modules = user_data['plugins']
    for plugin in modules:
        my_plugin = importlib.import_module('project.plugins.' + list(plugin.keys())[0])
        plugin = plugin.get(list(plugin.keys())[0])
        for method in plugin:  # modules = dict, module = str
            key_args = (method[list(method.keys())[0]])  # get key pair of method to run
            if key_args is None:
                key_args = {}
            method_to_call = getattr(my_plugin, list(method.keys())[0])  # get method name to run
            logging.critical("Running "+str(method_to_call)[:-15] + "for " + username)
            method_to_call(configMap, username, **key_args)


if __name__ == "__main__":
    main()
