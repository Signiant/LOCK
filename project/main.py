import argparse
import importlib
import logging
import logging.handlers
import os
import sys
import yaml
from project.plugins import iam
from project.plugins.iam import validate_new_key, get_new_key, create_and_test_key
from project.plugins.ec2 import list_instances,  get_instance_status, terminate_instance


def update_access_key(key):
    from project import values
    values.access_key = key


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

    logFormatter = logging.Formatter('%(asctime)s - %(message)s')
    rootLogger = logging.getLogger()
    fileHandler = logging.FileHandler("lock.log")
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)
    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    parser = argparse.ArgumentParser(description='LOCK Let\'s Occasionally Circulate Keys ')
    parser.add_argument('-u', '--user', help='aws user to rotate', required=False)
    parser.add_argument('-c', '--config', help='Full path to a config file', required=True)
    parser.add_argument('-a', '--action', help='Select the action to run: keys, rotate, validate', required=True)
    parser.add_argument('-k', '--key', help='Manually enter new key by skipping get_new_key method', required=False)
    parser.add_argument('-i', '--instance', help='The instance to act on.',required=False)

    args = parser.parse_args()
    configMap = readConfigFile(args.config)

    username = 'test_lock'  # args.user
    args.action = 'rotate'  # 'instance:status'   # run mode
    args.key = ('', '')
    args.instance = ''

    #create_and_test_key(configMap, username) # creates a key and 'adds a last used date'

    all_users = configMap['Users']
    for userdata in all_users:
        if username == (next(iter(userdata))):
            user_data = userdata.get(username)

    if 'user_data' not in locals() and username != 'all':
        print(username+' does not exist in the config file.')
        sys.exit()

    # get manually entered key, if any
    if args.key is not None:
        update_access_key(args.key)

    # key_args = {}
    if args.action == 'list':
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
                rotate_update(configMap, user_data, username)
        else:
            rotate_update(configMap, user_data, username)

    elif args.action == 'validate':  # validate that new key is being used and delete the old unused key
        logging.critical(validate_new_key(configMap, username))

    elif args.action == 'getnewkey':  # if you only want to
        get_new_key(configMap, username)

    elif args.action == 'instance:ids':
        instances = user_data['instances']

        list_instances(configMap, instances)

    elif args.action == 'instance:terminate':
        if args.instance is not None:
            key_args = {'instance_id': args.instance}
            terminate_instance(configMap, **key_args)
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
