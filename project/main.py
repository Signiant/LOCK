import argparse
import importlib
import logging
import os
import sys

import yaml
from project.plugins import ssh, pingdom , mail , iam
from project.plugins.iam import validate_new_key, get_new_key
from project.plugins.jenkins import update_credential


def update_access_key(newValue):
    from project import values
    values.access_key=newValue


def readConfigFile(path):
    configMap = []
    try:
        config_file_handle = open(path)
        configMap = yaml.load(config_file_handle)
        config_file_handle.close()
    except:
        print
        "Error: Unable to open config file %s or invalid yaml" % path
    return configMap

def main():
    logging.basicConfig(filename='info.log', level=logging.INFO)

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    parser = argparse.ArgumentParser(description='LOCK Let\'s Occasionaly Circulate Keys ')
    parser.add_argument('-u', '--user', help='aws user to rotate', required=False)
    parser.add_argument('-c', '--config', help='Full path to a config file', required=True)
    parser.add_argument('-m', '--mode', help='Select the mode to run: keys, rotate, validate', required=True)
    parser.add_argument('-k', '--key', help='Manually enter new key by skipping get_new_key method', required=False)

    #modes: list keys, rotate, validate, inactivate old key anyway?
    args = parser.parse_args()
    configMap = readConfigFile(args.config)

    username='test_lock' #args.user, aws user
    args.mode = 'rotate'   # run mode
    #args.key=(('AKIAAAS', 'XXXXXXX'))

    for userdata in configMap['Users']:
        if username == (next(iter(userdata))):
            user_data = userdata.get(username)

    #get manually entered key if any
    if args.key is not None:
        update_access_key(args.key)

    if args.mode == 'keys':
        iam.list_keys(configMap, username)

    elif args.mode == 'rotate':
        modules = user_data['plugins']
        for plugin in modules:
            my_plugin= importlib.import_module('project.plugins.'+list(plugin.keys())[0])
            plugin=plugin.get(list(plugin.keys())[0])
            for method in plugin: # modules = dict, module = str
                key_args = method[list(method.keys())[0]] #get key pair of method to run
                if key_args == None:
                      key_args = {}
                method_to_call = getattr(my_plugin, list(method.keys())[0]) # get method name to run
                returned_data = method_to_call(configMap, username,  **key_args) # need extra for params, data = data returned from previous method

    elif args.mode == 'validate':  #validate that new key is being used and delete the old unused key
        print(validate_new_key(configMap, username))

    elif args.mode == 'getnewkey':  #validate that new key is being used and delete the old unused key
        get_new_key(configMap, username)


    print("")


if __name__ == "__main__":
    main()
