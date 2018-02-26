from project.mail import emailOutput
from project.plugins.iam import get_client, get_access_keys, delete_inactive_key, create_key, get_iam_client, \
    validate_new_key, create_and_test_key, key_last_used
from project.plugins.parameterstore import insert_parameter

def start(configMap, username):

    for userdata in configMap['Users']:
        if username==(next(iter( userdata))):
            user_data=userdata.get( username)

    # setup connection
    client = get_iam_client(configMap)

    # get existing keys
    oldkeys = get_access_keys(client, username)

    # delete inactive keys (if any)
    print(delete_inactive_key(client, oldkeys, username))

    # create a new key
    new_key = create_key(client, username)
    print('new key: ' + str(new_key))

    #write key to param store
    insert_parameter(new_key, username, configMap)

    #email to ...
    emailOutput(user_data['mail']['mail_address'], configMap, username)


