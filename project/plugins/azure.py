import logging
from azure.keyvault import KeyVaultClient
from azure.mgmt.resource import ResourceManagementClient
from msrestazure.azure_active_directory import  UserPassCredentials
from project.plugins.ssh import ssh_server_command


def rotate_autoscalers_cloud(configMap, username,  **key_args):

    username = key_args.get('azure_admin')
    password = key_args.get('azure_admin_pw')
    subscription_id = key_args.get('subscription_id')
    credentials = UserPassCredentials(username, password)
    client = ResourceManagementClient(credentials, subscription_id)
    to_rotate = []

    for group in key_args.get('resource_group'):

        region = key_args.get('resource_group').get(group)
        region_strings = region.split('-')
        print(region_strings)
        ressource_groups = client.resources.list_by_resource_group(group)

        for item in ressource_groups:
            # print(item)
            if item.type == 'Microsoft.Compute/virtualMachines':
                if any(x in item.name for x in region_strings):
                    print(item.name)
                    to_rotate.append(item.name)

        print(to_rotate)
        for vm in to_rotate:
            if 'autoscaler' in vm:
                key_args['hostname'] = key_args.get('autoscaler_host').replace('<SERVER>', vm).replace('<REGION>', region.replace('-', ''))
                print(key_args['hostname'])
                for pkey in key_args.get('pkeys'):
                    if region.replace('-','') in pkey:
                        key_args['pkey'] = pkey
                key_args['commands'] = key_args['commands_autoscaler']
                key_args['markers'] = key_args['autoscaler_markers']
                #print(key_args)
                ssh_server_command(configMap, username, **key_args)
                logging.critical("Access key and Secret key written to "+ vm)
            else:  # its a flight server
                key_args['hostname'] = key_args.get('flight_host').replace('<SERVER>', vm).replace('<REGION>', region.replace('-', ''))
                print(key_args['hostname'])
                for pkey in key_args.get('pkeys'):
                    if region.replace('-', '') in pkey:
                        key_args['pkey'] = pkey
                key_args['commands'] = key_args['commands_flight']
                key_args['markers'] = key_args['flight_markers']
                #print(key_args)
                ssh_server_command(configMap, username, **key_args)
                logging.critical("Access key and Secret key written to " + vm)


def set_key_vault(configMap, username,  **key_args):

    username = key_args.get('azure_admin')
    password = key_args.get('azure_admin_pw')
    key_vault_uri = key_args.get('vault_uri')
    credentials = UserPassCredentials(username, password, resource='https://vault.azure.net')
    client = KeyVaultClient(credentials)

    from project import values
    client.set_secret(key_vault_uri, key_args.get('key_name'),  values.access_key[0])
    client.set_secret(key_vault_uri, key_args.get('key_secret'), values.access_key[1])
    logging.critical("Access key and Secret key written to key vault")
