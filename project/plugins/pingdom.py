import requests


def pingdom_pause_check(configMap, username, data, **key_args):

    PINGDOM_ACCOUNT_EMAIL = configMap['Global']['pingdom']['account_email']
    API_KEY = configMap['Global']['pingdom']['api_key']
    PINGDOM_USER = configMap['Global']['pingdom']['username']
    PINGDOM_PSWD = configMap['Global']['pingdom']['password']
    checks_to_pause = key_args.values()

    for checkid in checks_to_pause:
        url = "https://api.pingdom.com/api/2.1/checks/<checkid>?paused=true".replace('<checkid>', str(checkid))
        resp = requests.put(url,  headers={'Account-Email': PINGDOM_ACCOUNT_EMAIL, 'App-Key': API_KEY}, auth=(PINGDOM_USER, PINGDOM_PSWD))


def pingdom_unpause_check(configMap, username, data, **key_args):
    PINGDOM_ACCOUNT_EMAIL = configMap['Global']['pingdom']['account_email']
    API_KEY = configMap['Global']['pingdom']['api_key']
    PINGDOM_USER = configMap['Global']['pingdom']['username']
    PINGDOM_PSWD = configMap['Global']['pingdom']['password']
    checks_to_unpause = key_args.values()

    for checkid in checks_to_unpause:
        url = "https://api.pingdom.com/api/2.1/checks/<checkid>?paused=false".replace('<checkid>', str(checkid))
        resp = requests.put(url, headers={'Account-Email': PINGDOM_ACCOUNT_EMAIL, 'App-Key': API_KEY},
                            auth=(PINGDOM_USER, PINGDOM_PSWD))
        print(resp)
