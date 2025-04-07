from onepassword import (
    Client,
    Item,
    ItemCategory,
    ItemCreateParams,
    ItemField,
    ItemFieldType,
)
from project import values as project_values

import os
import asyncio
import logging


def update_item(
    client: Client,
    username: str,
    item: Item,
    category: str,
    title: str,
    value: str,
    tags: str = None,
    custom_fields: list = None,
) -> None:
    logging.info(f"User {username}: Updating item {title}...")

    item.category = getattr(ItemCategory, category)
    item.tags = tags if tags is not None else []

    for field in item.fields:
        if field.title == "value":
            field.value = value
            continue

        for custom_field in custom_fields:
            if custom_field["title"] == field.title:
                field.field_type = getattr(ItemFieldType, custom_field["type"])
                field.value = custom_field["value"]

    if project_values.DryRun:
        logging.info(f"User {username}: Dry Run enabled. {title} will not be updated.")
        return

    asyncio.run(client.items.put(item))
    logging.info(f"User {username}: {title} has been updated.")


def create_item(
    client: Client,
    username: str,
    vault_id: str,
    category: str,
    title: str,
    value: str,
    tags: str = None,
    custom_fields: list = None,
) -> None:
    logging.info(f"User {username}: Creating item {title}...")

    fields = [
        ItemField(
            id="value",
            title="value",
            fieldType=ItemFieldType.CONCEALED,
            value=value,
        )
    ]
    if custom_fields is not None:
        for field in custom_fields:
            fields.append(
                ItemField(
                    id=field["title"],
                    title=field["title"],
                    fieldType=getattr(ItemFieldType, field["type"]),
                    value=field["value"],
                )
            )

    category = getattr(ItemCategory, category)

    params = ItemCreateParams(
        title=title,
        category=category,
        vaultId=vault_id,
        fields=fields,
        tags=tags,
    )

    if project_values.DryRun:
        logging.info(f"User {username}: Dry Run enabled. {title} will not be created.")
        return

    asyncio.run(client.items.create(params))
    logging.info(f"User {username}: {title} has been created.")


def get_item_id(client: Client, vault_id: str, item_title: str) -> str:
    item_id = None
    items = asyncio.run(client.items.list_all(vault_id))
    for item in items.obj:
        if item.title == item_title:
            item_id = item.id
            break
    return item_id


def get_vault_id(client: Client, vault_title: str) -> str:
    vault_id = None
    vaults = asyncio.run(client.vaults.list_all())
    for vault in vaults.obj:
        if vault.title == vault_title:
            vault_id = vault.id
            break
    return vault_id


def validate_item_config(
    title: str,
    vault: str,
    category: str,
    value_type: str,
    tags: str,
    custom_fields: list,
) -> list:
    misconfigured_items = []

    if title is None:
        misconfigured_items.append("'title' is missing")

    if vault is None:
        misconfigured_items.append("'vault' is missing")

    if category is None:
        misconfigured_items.append("'category' is missing")
    else:
        if not hasattr(ItemCategory, category):
            misconfigured_items.append(f"'category' {category} does not exist")

    if value_type is None:
        misconfigured_items.append("'value_type' is missing")
    elif value_type not in ("key_id", "secret_key"):
        misconfigured_items.append(
            "'value_type' must be either 'key_id' or 'secret_key'"
        )

    if tags is not None and type(tags) != list:
        misconfigured_items.append("'tags' must be a list")

    if custom_fields is not None and type(custom_fields) != list:
        misconfigured_items.append("'custom_fields' must be a list")
    elif custom_fields is not None and type(custom_fields) == list:
        invalid_fields = []
        for i, field in enumerate(custom_fields):
            invalid_items = []
            if "title" not in field:
                invalid_items.append("'title' is missing")
            if "value" not in field:
                invalid_items.append("'value' is missing")
            if "type" not in field:
                invalid_items.append("'type' is missing")
            else:
                if not hasattr(ItemFieldType, field["type"]):
                    invalid_items.append(f"{field["type"]} is not a valid field type")

            if len(invalid_items) > 0:
                invalid_fields.append(
                    f"Field {i} is misconfigured: {", ".join(invalid_items)}"
                )

        if len(invalid_fields) > 0:
            misconfigured_items.append(
                f"One or more 'custom_fields' items are misconfigured ({", ".join(invalid_fields)})"
            )

    return misconfigured_items


def upsert_items(_: dict, username: str, **kwargs: dict) -> None:
    token = os.getenv("OP_SERVICE_ACCOUNT_TOKEN")
    if token is None:
        logging.error(
            f"User {username}: OP_SERVICE_ACCOUNT_TOKEN is not set. Unable to upsert items."
        )
        return

    client = asyncio.run(
        Client.authenticate(
            auth=token, integration_name="LOCK", integration_version="v1.0.0"
        )
    )

    items = kwargs.get("items")

    if items is None:
        logging.error(
            f"User {username}: Config item 'items' for 1password.upsert_items is missing."
        )
        return

    for i, item_config in enumerate(items):
        item_title = item_config.get("title")
        vault_title = item_config.get("vault")
        category = item_config.get("category")
        value_type = item_config.get("value_type")
        tags = item_config.get("tags")
        custom_fields = item_config.get("custom_fields")

        misconfigured_items = validate_item_config(
            item_title, vault_title, category, value_type, tags, custom_fields
        )
        if len(misconfigured_items) > 0:
            logging.error(
                f"User {username}: Item {i + 1} with title {item_title} will be skipped due to an invalid config: {", ".join(misconfigured_items)}"
            )
            continue

        value = (
            project_values.access_keys[username][0]
            if value_type == "key_id"
            else project_values.access_keys[username][1]
        )

        vault_id = get_vault_id(client, vault_title)
        if vault_id is None:
            logging.error(
                f"User {username}: Unable to get {item_title} from {vault_title}: Vault not found."
            )
            continue

        item_id = get_item_id(client, vault_id, item_title)
        if item_id is None:
            item = None
        else:
            item = asyncio.run(client.items.get(vault_id, item_id))

        if item is None:
            logging.info(
                f"User {username}: {item_title} does not exist in vault {vault_title}"
            )
            create_item(
                client,
                username,
                vault_id,
                category,
                item_title,
                value,
                tags,
                custom_fields,
            )
        else:
            logging.info(
                f"User {username}: {item_config["title"]} already exists in vault {item_config["vault"]}"
            )
            update_item(
                client,
                username,
                item,
                category,
                item_title,
                value,
                tags,
                custom_fields,
            )
