import logging
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from bs4 import BeautifulSoup
from project import values

path = os.path.dirname(__file__)


def mail_message(configMap, username,  **key_args):

    # Get the SMTP config
    smtp_server = configMap['Global']['smtp']['server']
    smtp_tls = configMap['Global']['smtp']['tls']
    smtp_port = configMap['Global']['smtp']['port']
    smtp_user = configMap['Global']['smtp']['user']
    smtp_pass = configMap['Global']['smtp']['password']
    smtp_from = configMap['Global']['smtp']['from_addr']
    smtp_cc = configMap['Global']['smtp']['cc_addrs']
    if key_args.get('mail_to_cc') is not None:
        for email in key_args.get('mail_to_cc'):
            smtp_cc.append(email)
    email_template_file = configMap['Global']['smtp']['template']

    # for userdata in configMap['Users']:
    #     if username == (next(iter(userdata))):
    #         user_data = userdata.get(username)

    email_to_addr = key_args.get('mail_to')
    email_subject = "AWS key rotation"
    content_title = key_args.get('mail_message').replace("<name>", 'LOCK.'+username.upper())

    htmlvalues = {}

    # insert htmlvalues
    template = EmailTemplate(template_name=email_template_file, htmlvalues=htmlvalues,content_title=content_title)

    server = MailServer(server_name=smtp_server, username=smtp_user, password=smtp_pass, port=smtp_port, require_starttls=smtp_tls)

    msg = MailMessage(from_email=smtp_from, to_emails=[email_to_addr], cc_emails=smtp_cc,subject=email_subject,template=template)

    if values.DryRun is True:
        logging.info('Dry run: mail_message; ' + content_title)
    else:
        send(mail_msg=msg, mail_server=server)
        logging.critical("Notification email sent to " + key_args.get('mail_to') + ' cc: '+ str(smtp_cc))


class MailServer(object):
    msg = None

    def __init__(self, server_name='<server_name>', username='<username>', password='<password>', port='<smtp_port>', require_starttls=True):
        self.server_name = server_name
        self.username = username
        self.password = password
        self.port = port
        self.require_starttls = require_starttls

class EmailTemplate():
    def __init__(self, template_name='', htmlvalues='', html=True, content_title=''):
        self.template_name = template_name
        self.htmlvalues = htmlvalues
        self.html = html
        self.content_title=content_title

    def render(self):
        path = os.path.dirname(__file__)
        try:
            content1 = open(path +"/" + self.template_name).read()
        except: #run as PyPI
            path="project"
            content1 = open(path +"/" + self.template_name).read()

        html=BeautifulSoup(content1, 'html.parser')
        html.find("div",{"id":'title'}).append(self.content_title)
        count=1

        return str(html)


# author Dave North
class MailMessage(object):
    html = False

    def __init__(self, from_email='', to_emails=[], cc_emails=[], subject='', body='', template=None):
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

        if len(self.to_emails) == 0 or self.from_email == '':
            raise ValueError('Invalid From or To email address(es)')

        msg = MIMEMultipart('alternative')
        msg['To'] = ', '.join(self.to_emails)
        msg['Cc'] = ', '.join(self.cc_emails)
        msg['From'] = self.from_email
        msg['Subject'] = self.subject
        if self.template:
            #If the template is html, attach and set MIME
            if self.template.html:
                #Attach plain text, which will be used if a template cannot render
                #The last attached element will always take precedence (according to RFC2046)
                msg.attach(MIMEText(self.body, 'plain'))
                msg.attach(MIMEText(self.template.render(),'html'))
            #Otherwise, attach plaintext template
            else:
                msg.attach(MIMEText(self.template.render(), 'plain'))
        else:
                msg.attach(MIMEText(self.body, 'plain'))
        return msg


def send(mail_msg, mail_server=MailServer()):
    server = smtplib.SMTP(mail_server.server_name, mail_server.port)
    if mail_server.require_starttls:
        server.starttls()
    if mail_server.username:
        server.login(mail_server.username, mail_server.password)
    response=server.sendmail(mail_msg.from_email, (mail_msg.to_emails + mail_msg.cc_emails), mail_msg.get_message().as_string())
    server.close()


