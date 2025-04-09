from jenkinsapi.credential import UsernamePasswordCredential
from jenkinsapi.jenkins import Jenkins
from jenkinsapi.utils.crumb_requester import CrumbRequester
from project import values

import logging


# https://github.com/pycontribs/jenkinsapi/blob/master/examples/how_to/create_credentials.py
def update_credential(config_map, _, **key_args):
    auth = config_map["Global"]["server"]["jenkins"]
    username = auth.get("user")
    password = auth.get("password")
    jenkins_url = key_args.get("url")
    creds_description1 = key_args.get("credential_description")

    try:
        jenkins = Jenkins(
            jenkins_url,
            username=username,
            password=password,
            requester=CrumbRequester(
                baseurl=jenkins_url, username=username, password=password
            ),
        )

        creds = jenkins.credentials

        cred_dict = {
            "description": creds_description1,
            "userName": values.access_keys[username][0],
            "password": values.access_keys[username][1],
        }
        if values.DryRun is True:
            logging.info(f"User {username}: Dry run: " + jenkins_url)
        else:
            try:
                creds[creds_description1] = UsernamePasswordCredential(cred_dict)
                logging.info(f"User {username}: Key written to " + jenkins_url)
            except Exception as e:
                logging.error(
                    f"User {username}: Key write failed at {jenkins_url}: {e}"
                )
    except Exception as e:
        logging.error(
            f"User {username}: Exception trying to modify Key at {jenkins_url} (Key may need to be updated manually): {e}"
        )
