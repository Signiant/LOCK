import argparse
import importlib
import logging
import os
import sys
import yaml
from project.plugins import ssh, pingdom , mail , iam
from project.plugins.iam import validate_new_key, get_new_key
from project.plugins.ec2 import list_instances, stop_instance, get_instance_status


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
    parser.add_argument('-i', '--instance', help='The instance to act on.',required=False)
    # parser.add_argument('-s', '--stop', help='Stop an instance.',  action='store_true',required=False)

    args = parser.parse_args()
    configMap = readConfigFile(args.config)

    username='' #args.user, aws user
    args.mode = 'rotate'   # run mode
    args.key=(('', '')) #fake test key
    args.instance= ''


    for userdata in configMap['Users']:
        if username == (next(iter(userdata))):
            user_data = userdata.get(username)

    #get manually entered key if any
    if args.key is not None:
        update_access_key(args.key)

    key_args = {}
    if args.mode == 'keys':
        iam.list_keys(configMap, username)

    elif args.mode == 'rotate':
        modules = user_data['plugins']
        pass_data = None
        for plugin in modules:
            my_plugin = importlib.import_module('project.plugins.'+list(plugin.keys())[0])
            plugin=plugin.get(list(plugin.keys())[0])
            for method in plugin: # modules = dict, module = str
                key_args.update(method[list(method.keys())[0]])  #get key pair of method to run
                if key_args == None:
                      key_args = {}
                method_to_call = getattr(my_plugin, list(method.keys())[0]) # get method name to run
                pass_data = method_to_call(configMap, username, **key_args) # need extra for params, data = data returned from previous method

    elif args.mode == 'validate':  #validate that new key is being used and delete the old unused key
        print(validate_new_key(configMap, username))

    elif args.mode == 'getnewkey': # if you only want to
        get_new_key(configMap, username)

    elif args.mode == 'instance:ids':
        modules = user_data['plugins']
        for plugin in modules:
            plugin = plugin.get(list(plugin.keys())[0])
            for method in plugin:
                key_args.update(method[list(method.keys())[0]])
                list_instances(configMap, **key_args)

    elif args.mode == 'instance:stop':
        if args.instance is not None:
            key_args = {'instance_id': args.instance}
            stop_instance(configMap, **key_args)
        else:
            print("Provide an instance id. '-i xxxxxx'")

    elif args.mode == 'instance:status':
        if args.instance is not None:
             key_args = {'instance_id': args.instance}
             get_instance_status(configMap, **key_args)
        else:
            print("Provide an instance id. '-i xxxxxx' ")

    print("")




if __name__ == "__main__":
    main()
