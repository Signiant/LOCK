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

