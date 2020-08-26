"""
command line application and sample code for accessing a secret version.
"""

import logging
from google.cloud import secretmanager
from google.auth import compute_engine

def set_secret_manager(configMap, username,  **key_args):
    auth = configMap['Global']['google_credentials']['client_cred']

    # Create the Secret Manager client.
    try:
        client = secretmanager.SecretManagerServiceClient.from_service_account_json(auth)
    except Exception as e:
        logging.error("Error: {0}".format(e))
        return


    # Convert the string payload into a bytes. This step can be omitted if you
    # pass in bytes instead of a str for the payload argument.
    
    from project import values
    if values.DryRun is True:
        logging.info('Dry run ')
    else:

        # Build the resource name of the parent secret.
        try: 
            parent_access = client.secret_path(key_args.get('project_id'), key_args.get('key_name'))
            payload_access = values.access_key[0].encode('UTF-8')
            response = client.add_secret_version(parent_access, {'data': payload_access})
            logging.debug("Response: {0}".format(response))
        except Exception as e:
            logging.error("     ***** Exception trying to update Google Access Key - Key may need to be updated manually. Exception: {0}".format(e))
            return
        try: 
            parent_secret = client.secret_path(key_args.get('project_id'), key_args.get('key_secret'))
            payload_secret = values.access_key[1].encode('UTF-8')
            response = client.add_secret_version(parent_secret, {'data': payload_secret})
            logging.debug("Response: {0}".format(response))
        except Exception as e:
            logging.error("     ***** Exception trying to update Google Secret Key - Key may need to be updated manually. Exception: {0}".format(e))
            return

        logging.info("      Access key and Secret key written to Secret Manager")
        pass
