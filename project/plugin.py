import ast
import imp,os

from project.plugins import iam, mail, pingdom, ssh
from project.plugins.iam import get_iam_client, get_access_keys, key_last_used

pluginFolder = "../project/plugins"
mainFile = "__init__"


def getAllPlugins():
    plugins = []
    possibleplugins = os.listdir(pluginFolder)
    for i in possibleplugins:
        location = os.path.join(pluginFolder, i)
        if not os.path.isdir(location) or not mainFile + ".py" in os.listdir(location):
            continue
        info = imp.find_module(mainFile, [location])
        plugins.append({"name": i, "info": info})
    return plugins

def loadPlugin(pluginName):
    return imp.load_source(pluginName, os.path.join(pluginFolder, pluginName, mainFile + ".py"))

def get_new_key(configMap, username, data, **kwargs):
    return iam.get_new_key(configMap, username, data, **kwargs)

def store_key_parameter_store( configMap, username, new_key ):
    iam.store_key_parameter_store(configMap, username, new_key)

def mail_message(configMap, username, data, **key_args):
    mail.mail_message(configMap, username, data,**key_args)
def pingdom_pause_check(configMap, username, data, **key_args):
    pingdom.pingdom_pause_check(configMap, username, data, **key_args)

def pingdom_unpause_check(configMap, username, data, **key_args):
    pingdom.pingdom_unpause_check(configMap, username, data, **key_args)

def dummy(configMap, username, data, **key_args):
    print (dummy)

def write_new_key(configMap, username, data, **key_args):
    ssh.write_new_key(configMap, username, data, **key_args)

def list_keys(configMap,username):
    client=get_iam_client(configMap)
    keys=get_access_keys(client, username)
    for key in keys:
        response=(key_last_used(client,key.get('AccessKeyId')))
        key["Last Used"] =response.get('AccessKeyLastUsed').get('LastUsedDate')
        print('')
        for i in key:
            print (i, ':',key[i])