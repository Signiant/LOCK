from project import values

import json
import logging
import subprocess


def upsert_item(action: str, username: str, vault: str, category: str, title: str, value: str,  tags: str = None, custom_fields: list = None,  item: dict = None) -> None:
    logging.info(f"User {username}: Upserting item {title}...")

    cmd = ["op", "item", action, "--vault", vault]

    if values.DryRun:
        cmd += ["--dry-run"]

    if action == "edit":
        cmd += [title]

        new_tags = []
        if tags is not None:
            new_tags = [tag for tag in tags.split(",") if tag not in item["tags"]]
        if len(new_tags) > 0:
            cmd += ["--tags"] + new_tags
    else:
        cmd += ["--title", title]
        if tags is not None:
            cmd += ["--tags", tags]
        cmd += ["--category", category]

    cmd += [f"value={value}"]
    if custom_fields is not None:
        cmd += [field for field in custom_fields]

    try:
        logging.info(f"User {username}: running command: {' '.join(cmd).replace(f"value={value}", "value=REDACTED")}")
        # Not sure what it is about Pycharm and the 'create' or 'edit' commands, but it WILL NOT work if the script is executed
        # using Pycharm.
        response = subprocess.run(cmd, timeout=10, capture_output=True, text=True)
    except subprocess.TimeoutExpired as e:
        logging.error(f"User {username}: Failed to upsert {title}: {e}")
        return

    if response.returncode != 0:
        logging.error(f"User {username}: Failed to upsert {title}. Output of command: \"{response.stderr.strip()}\".")
    else:
        logging.info(f"User {username}: Successfully upserted {title}. Output of command:\n{response.stdout}")


def get_item(vault: str, title: str) -> tuple:
    response = None
    cmd = ["op", "item", "get", "--format", "json", "--vault", vault, title]

    try:
        response = subprocess.run(cmd, timeout=10, capture_output=True, text=True)
    except subprocess.TimeoutExpired as e:
        logging.error(e)

    if response is None:
        return None, None
    elif response.returncode != 0:
        return response.returncode, response.stderr
    else:
        return response.returncode, response.stdout


def validate_item_config(title: str, vault: str, category: str, value_type: str, tags: str, custom_fields: list) -> list:
    misconfigured_items = []

    if title is None:
        misconfigured_items.append("'title' is missing")

    if vault is None:
        misconfigured_items.append("'vault' is missing")

    if category is None:
        misconfigured_items.append("'category' is missing")

    if value_type is None:
        misconfigured_items.append("'value_type' is missing")
    elif value_type not in ("key_id", "secret_key"):
        misconfigured_items.append("'value_type' must be either 'key_id' or 'secret_key'")

    if tags is not None and type(tags) != str:
        misconfigured_items.append("'tags' must be type str")

    if custom_fields is not None and type(custom_fields) != list:
        misconfigured_items.append("'custom_fields' must be a list")

    return misconfigured_items


def upsert_items(_: dict, username: str, **kwargs: dict) -> None:
    items = kwargs.get("items")

    if items is None:
        logging.error(f"User {username}: Config item 'items' for 1password.upsert_items is missing.")
        return

    for i, item_config in enumerate(items):
        title = item_config.get("title")
        vault = item_config.get("vault")
        category = item_config.get("category")
        value_type = item_config.get("value_type")
        tags = item_config.get("tags")
        custom_fields = item_config.get("custom_fields")

        misconfigured_items = validate_item_config(title, vault, category, value_type, tags, custom_fields)
        if len(misconfigured_items) > 0:
            logging.error(f"User {username}: Item {i + 1} with title {title} will be skipped due to an invalid config: {", ".join(misconfigured_items)}")
            continue

        value = values.access_key[0] if value_type == "key_id" else values.access_key[1]

        code, output = get_item(vault, title)
        if code is None and output is None:
            logging.warning(f"User {username}: An error occurred trying to retrieve {title} from 1Password. Skipping to next item...")
            continue

        if code != 0:
            logging.info(f"User {username}: {title} does not exist in vault {vault}")
            upsert_item("create", username, vault, category, title, value, tags, custom_fields)
        else:
            logging.info(f"User {username}: {item_config["title"]} already exists in vault {item_config["vault"]}")
            item_data = json.loads(output)
            upsert_item("edit", username, vault, category, title, value, tags, custom_fields, item_data)
