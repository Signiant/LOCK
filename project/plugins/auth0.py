import json
import logging
from project import values
import requests


def rotate_auth0_key(configMap, username, **key_args):

    auth = configMap['Global']['auth0_email_sender'][key_args.get('account')]
    client_id = auth.get('client_id')
    client_secret = auth.get('client_secret')

    headers = {'Content-Type': 'application/JSON; charset=utf-8'}

    data = '{"client_id": "' + client_id + '",'\
         '"client_secret":"'+client_secret+'",' \
         '"audience":"'+key_args.get('url_api')+'",' \
         '"grant_type":"client_credentials"}'

    # get access token
    response = requests.post(key_args.get('url_auth'), headers=headers, data=data)
    data = response.content.decode('utf8')
    data = json.loads(data)
    access_token = data['access_token']
    auth = {'Authorization': 'Bearer ' + access_token}

    # set new key values
    response = requests.get(key_args.get('url_api') + 'emails/provider?fields=credentials%2Cname%2Cdefault_from_address%2Csettings%2Cenabled&include_fields=true', headers=auth)
    data = response.content.decode('utf8')
    data = json.loads(data)
    data['credentials']['accessKeyId'] = values.access_keys[username][0]
    data['credentials']['secretAccessKey'] = values.access_keys[username][1]
    data = json.dumps(data)
    header_auth = {**auth, **headers}
    if values.DryRun is True:
        logging.info(f'User {username}: Dry run, patch Auth0:' + data)
    else:
        response = requests.patch(key_args.get('url_api') + 'emails/provider', headers=header_auth, data=data)
        if response.status_code == 200:
            logging.info(f"User {username}: Auth0 email provider access key updated")
        else:
            logging.error(f"User {username}: Auth0 key update has not completed")

