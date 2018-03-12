import json

from project import values


def rotate_auth0_key(configMap, username,  **key_args):

    import requests

    headers = {'Content-Type': 'application/JSON; charset=utf-8' }


    data='{"client_id": "'+ key_args.get('client_id')+'",' \
         '"client_secret":"'+key_args.get('client_secret')+'",' \
         '"audience":"'+key_args.get('url_api')+'",' \
         '"grant_type":"client_credentials"}'

    response = requests.post(key_args.get('url_auth'), headers=headers, data=data)
    print(response)

    data = response.content.decode('utf8')
    data = json.loads(data)
    access_token=data['access_token']
    auth = {'Authorization': 'Bearer '+ access_token}
    response= requests.get(key_args.get('url_api')+'emails/provider?fields=credentials%2Cname%2Cdefault_from_address%2Csettings%2Cenabled&include_fields=true', headers=auth)
    print(response)

    data = response.content.decode('utf8')
    data = json.loads(data)
    data['credentials']['accessKeyId'] = values.access_key[0]
    data['credentials']['secretAccessKey'] = values.access_key[1]
    print(data)
    data=json.dumps(data)
    header_auth = {**auth, **headers }
    response = requests.patch(key_args.get('url_api')+'emails/provider',headers=header_auth, data=data )
    print(response)

