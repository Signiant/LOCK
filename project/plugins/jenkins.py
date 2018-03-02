from jenkinsapi.credential import UsernamePasswordCredential
from jenkinsapi.jenkins import Jenkins
from jenkinsapi.utils.crumb_requester import CrumbRequester
from project import values


def update_credential(configMap, username,  **key_args): #https://github.com/pycontribs/jenkinsapi/blob/master/examples/how_to/create_credentials.py
    if  values.access_key==("",""):
        print('no key set, skipping method update_credential')
    else:
        jenkins_url = key_args.get('url')
        username = key_args.get('user')
        password = key_args.get('password')
        creds_description1 = key_args.get('credential_description')

        jenkins = Jenkins(jenkins_url, username=username, password=password,
                          requester=CrumbRequester(baseurl=jenkins_url, username=username, password=password))

        creds = jenkins.credentials

        cred_dict = {
            'description': creds_description1,
            'userName': values.access_key[0],
            'password': values.access_key[1]
        }
        creds[creds_description1] = UsernamePasswordCredential(cred_dict)
