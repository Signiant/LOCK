import ast
import imp,os

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

def list_keys(configMap,username):
    client=get_iam_client(configMap)
    keys=get_access_keys(client, username)
    for key in keys:
        response=(key_last_used(client,key.get('AccessKeyId')))
        key["Last Used"] =response.get('AccessKeyLastUsed').get('LastUsedDate')
        print('')
        for i in key:
            print (i, ':',key[i])