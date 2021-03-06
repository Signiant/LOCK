import logging

from jenkinsapi.credential import UsernamePasswordCredential
from jenkinsapi.jenkins import Jenkins
from jenkinsapi.utils.crumb_requester import CrumbRequester
from project import values


# https://github.com/pycontribs/jenkinsapi/blob/master/examples/how_to/create_credentials.py
def update_credential(configMap, username,  **key_args):
        auth = configMap['Global']['server']['jenkins']
        username = auth.get('user')
        password = auth.get('password')
        jenkins_url = key_args.get('url')
        creds_description1 = key_args.get('credential_description')

        try:
            jenkins = Jenkins(jenkins_url, username=username, password=password,
                              requester=CrumbRequester(baseurl=jenkins_url, username=username, password=password))

            creds = jenkins.credentials

            cred_dict = {
                'description': creds_description1,
                'userName': values.access_key[0],
                'password': values.access_key[1]
            }
            if values.DryRun is True:
                logging.info('      Dry run: ' + jenkins_url)
            else:
                try:
                    creds[creds_description1] = UsernamePasswordCredential(cred_dict)
                    logging.info('      Key written to ' + jenkins_url )
                except:
                    logging.error('     Key write failed at: ' + jenkins_url )
        except:
            logging.error('     ***** Exception trying to modify Key at %s - Key may need to be updated manually' % jenkins_url )
