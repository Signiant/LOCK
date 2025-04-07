import logging
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import boto3
from botocore.exceptions import ClientError
from bs4 import BeautifulSoup

from project import values


def mail_message(configMap, username, **key_args):
    mail_from = configMap["Global"]["mail"]["from_addr"]
    mail_cc = configMap["Global"]["mail"]["cc_addrs"]
    if key_args.get("mail_to_cc") is not None:
        for email in key_args.get("mail_to_cc"):
            mail_cc.append(email)
    email_template_file = configMap["Global"]["mail"]["template"]

    email_to_addr = key_args.get("mail_to")
    email_subject = "AWS key rotation"
    content_title = key_args.get("mail_message").replace(
        "<name>", "LOCK." + username.upper()
    )

    htmlvalues = {}
    template = EmailTemplate(
        template_name=email_template_file,
        htmlvalues=htmlvalues,
        content_title=content_title,
    )

    msg = MailMessage(
        from_email=mail_from,
        to_emails=[email_to_addr],
        cc_emails=mail_cc,
        subject=email_subject,
        template=template,
    )

    if values.DryRun is True:
        logging.info(f"User {username}: Dry run: mail_message;\n" + content_title)
    else:
        send_ses(username, configMap, msg)
        logging.info(
            f"User {username}: Notification email sent to "
            + key_args.get("mail_to")
            + " cc: "
            + str(mail_cc)
        )


class EmailTemplate:
    def __init__(self, template_name="", htmlvalues="", html=True, content_title=""):
        self.template_name = template_name
        self.htmlvalues = htmlvalues
        self.html = html
        self.content_title = content_title

    def render(self):
        path = os.path.dirname(__file__)
        try:
            content1 = open(path + "/" + self.template_name).read()
        except:
            path = "project"
            content1 = open(path + "/" + self.template_name).read()

        html = BeautifulSoup(content1, "html.parser")
        html.find("div", {"id": "title"}).append(self.content_title)

        return str(html)


class MailMessage(object):
    html = False

    def __init__(
        self,
        from_email="",
        to_emails=[],
        cc_emails=[],
        subject="",
        body="",
        template=None,
    ):
        self.from_email = from_email
        self.to_emails = to_emails
        self.cc_emails = cc_emails
        self.subject = subject
        self.template = template
        self.body = body

    def get_message(self):
        if isinstance(self.to_emails, str):
            self.to_emails = [self.to_emails]

        if isinstance(self.cc_emails, str):
            self.cc_emails = [self.cc_emails]

        if len(self.to_emails) == 0 or self.from_email == "":
            raise ValueError("Invalid From or To email address(es)")

        msg = MIMEMultipart("alternative")
        msg["To"] = ", ".join(self.to_emails)
        msg["Cc"] = ", ".join(self.cc_emails)
        msg["From"] = self.from_email
        msg["Subject"] = self.subject
        if self.template:
            # If the template is html, attach and set MIME
            if self.template.html:
                # Attach plain text, which will be used if a template cannot render
                # The last attached element will always take precedence (according to RFC2046)
                msg.attach(MIMEText(self.body, "plain"))
                msg.attach(MIMEText(self.template.render(), "html"))
            # Otherwise, attach plaintext template
            else:
                msg.attach(MIMEText(self.template.render(), "plain"))
        else:
            msg.attach(MIMEText(self.body, "plain"))
        return msg


def send_ses(username, config_map, mail_msg):
    if values.profile is not None:
        session = boto3.Session(profile_name=values.profile, region_name="us-east-1")
        ses = session.client("ses")
    else:
        ses = boto3.client(
            "ses",
            aws_access_key_id=config_map["Global"]["id"],
            aws_secret_access_key=config_map["Global"]["secret"],
        )

    try:
        ses.send_raw_email(RawMessage={"Data": mail_msg.get_message().as_string()})
    except ClientError as e:
        error_message = e.response["Error"]["Message"]
        logging.error(f"User {username}: Error sending message: {error_message}")
