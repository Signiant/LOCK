import argparse
import logging
import os
import sys
import yaml
from project import plugin
from project.mail import emailOutput

from project.plugins.iam import get_client, get_access_keys, delete_inactive_key, create_key, get_iam_client, \
    validate_new_key, create_and_test_key
from project.plugins.parameterstore import insert_parameter
from project.plugins.ssh import write_key_to_yaml, run_command, SSH_server,write_new_key


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
    parser = argparse.ArgumentParser(description='External user provisioning tool')
    parser.add_argument('-u', '--user', help='aws user to rotate', required=False)
    parser.add_argument('-c', '--config', help='Full path to a config file', required=True)
    parser.add_argument('-v', '--validation', help='validation mode', required=False)
    parser.add_argument('-k', '--keys', help='show key instead', required=False)


    args = parser.parse_args()
    configMap = readConfigFile(args.config)


    username='test_lock'

    # create_and_test_key(configMap, username)
    # validate_new_key(configMap, username)
    # user_test_lock(configMap, username)
    insert_parameter(('aaaa', 'xxxxx'), username, configMap)


    #plugin_handle = plugin.loadPlugin(username)
    #plugin_handle.list_keys(configMap, username)

    print("")


def user_test_lock(configMap, username):

    for userdata in configMap['Users']:
        if username == (next(iter(userdata))):
            user_data = userdata.get(username)

    #new_key=rotate_aws_user_key(configMap, username)

    #bulk of code, write key id + secret to file
    #write_new_key(user_data, new_key)

    #save the key where its safe + retrievable
    insert_parameter(('aaaa','xxxxx'),username,configMap)

def rotate_aws_user_key(configMap, username):


    #setup connection
    client=get_iam_client( configMap)

    #get existing keys
    oldkeys=get_access_keys( client, username)

    #delete inactive keys
    print(delete_inactive_key( client, oldkeys, username))

    ##DELETE OLDEST USED KEY

    #create a new key
    new_key=create_key(client, username)
    print('new key: '+str(new_key))
    return new_key

if __name__ == "__main__":
    main()
