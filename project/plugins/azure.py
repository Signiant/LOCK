import logging
from azure.keyvault import KeyVaultClient
from azure.mgmt.resource import ResourceManagementClient
from msrestazure.azure_active_directory import UserPassCredentials, ServicePrincipalCredentials
from project.plugins.ssh import ssh_server_command


def rotate_autoscalers_cloud(configMap, username,  **key_args):

    auth = configMap['Global']['azure_credentials'][key_args.get('account')]

    credentials = ServicePrincipalCredentials(
        client_id=auth.get('client_id'),
        secret=auth.get('secret'),
        tenant=auth.get('tenant')
    )
    subscriptions = key_args.get('resource_group_subscriptionid')

    for sub in subscriptions:
        region = (list(sub.keys())[0])
        resource_group = list(sub.get(region).keys())[0]
        sub_id=sub.get(region).get(resource_group)
        client = ResourceManagementClient(credentials, sub_id)
        to_rotate = []

        ressource_groups = client.resources.list_by_resource_group(resource_group)

        for item in ressource_groups:
            if item.type == 'Microsoft.Compute/virtualMachines':
                    to_rotate.append(item.name)

        #Build dns names
        for vm in to_rotate:  # rotate key for server type
            markers = []
            commands = []
            if 'autoscaler' in vm:
                for host in key_args.get('autoscalers'):
                    r=region.replace('-', '')
                    if r in host:
                        key_args['hostname']=host
                logging.info('      Writing key to '+key_args['hostname'])
                for pkey in key_args.get('pkeys'):
                    if region.replace('-','') in pkey:
                        key_args['pkey'] = pkey

                for marker in key_args.get('autoscaler_markers_commands'):
                    markers.append(marker)
                    commands.append(key_args.get('autoscaler_markers_commands').get(marker))
                key_args['commands'] = commands
                key_args['markers'] = markers
                ssh_server_command(configMap, username, **key_args)
            else:  # its a flight server
                key_args['hostname'] = key_args.get('f_host').replace('<SERVER>', vm).replace('<REGION>', region.replace('-', ''))
                logging.info('      Writing key to '+key_args['hostname'])
                for pkey in key_args.get('pkeys'):
                    if region.replace('-', '') in pkey:
                        key_args['pkey'] = pkey
                for marker in key_args.get('fadmin_markers_commands'):
                    markers.append(marker)
                    commands.append(key_args.get('fadmin_markers_commands').get(marker))
                key_args['commands'] = commands
                key_args['markers'] = markers
                ssh_server_command(configMap, username, **key_args)


def set_key_vault(configMap, username,  **key_args):

    key_vault_uri = key_args.get('vault_uri')
    auth = configMap['Global']['azure_credentials'][key_args.get('account')]

    credentials = ServicePrincipalCredentials(
        client_id=auth.get('client_id'),
        secret=auth.get('secret'),
        tenant=auth.get('tenant')
    )

    client = KeyVaultClient(credentials)

    from project import values
    if values.DryRun is True:
        logging.info('Dry run ')
    else:
        client.set_secret(key_vault_uri, key_args.get('key_name'), values.access_key[0])
        client.set_secret(key_vault_uri, key_args.get('key_secret'), values.access_key[1])
        logging.info("      Access key and Secret key written to key vault")
        pass

