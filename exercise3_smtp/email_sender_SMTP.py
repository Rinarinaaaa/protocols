import json
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.header import Header
import mimetypes
from typing import Optional, List, Dict


class SMTPSender:

    DEFAULT_SERVERS = {
        'gmail.com': ('smtp.gmail.com', 587, 'starttls'),
        'mail.ru': ('smtp.mail.ru', 465, 'ssl'),
        'yandex.ru': ('smtp.yandex.ru', 465, 'ssl'),
        'outlook.com': ('smtp-mail.outlook.com', 587, 'starttls')
    }

    def __init__(self, config_path: str = 'config.json'):
        self.config = self.load_config(config_path)
        self.smtp_server, self.port, self.security = self.resolve_server_settings()
        self.text_content = self.read_message_file()

    def load_config(self, config_path: str) -> Dict:
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            required_fields = ['connection', 'message']
            for field in required_fields:
                if field not in config:
                    raise ValueError(f"{field}")

            return config
        except Exception as e:
            raise Exception(f"ошибка загрузки конфига: {str(e)}")

    def resolve_server_settings(self) -> tuple:
        if (self.config['connection'].get('smtp_server') != 'auto' and
                self.config['connection'].get('port') != 'auto'):
            return (
                self.config['connection']['smtp_server'],
                int(self.config['connection']['port']),
                self.config['connection'].get('security', 'auto')
            )
        domain = self.config['connection']['login'].split('@')[-1].lower()
        if domain in self.DEFAULT_SERVERS:
            return self.DEFAULT_SERVERS[domain]

        raise ValueError(f"неизвестный почтовый домен: {domain}")

    def read_message_file(self) -> str:
        msg_file = self.config['message'].get('text_file', 'message.txt')
        try:
            with open(msg_file, 'r', encoding=self.config['settings'].get('encoding', 'utf-8')) as f:
                return f.read()
        except Exception as e:
            raise Exception(f"ошибка чтения файла с сообщением: {str(e)}")

    def send_email(self):
        message = self.prepare_message()

        for attempt in range(self.config['settings'].get('retries', 3)):
            try:
                with self.create_smtp_connection() as server:
                    server.sendmail(
                        self.config['connection']['login'],
                        self.config['message']['recipients'],
                        message.as_string()
                    )
                print("письмо отправлено")
                return
            except Exception as e:
                print(f"ошибка - {str(e)}")
                if attempt == self.config['settings'].get('retries', 3) - 1:
                    raise

    def create_smtp_connection(self):
        if self.security == 'starttls':
            server = smtplib.SMTP(self.smtp_server, self.port,
                                  timeout=self.config['settings'].get('timeout', 30))
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(self.smtp_server, self.port,
                                      timeout=self.config['settings'].get('timeout', 30))

        server.login(
            self.config['connection']['login'],
            self.config['connection']['password']
        )
        return server

    def prepare_message(self) -> MIMEMultipart:
        msg = MIMEMultipart("mixed" if self.has_attachments else "alternative")
        msg['From'] = self.config['connection']['login']
        msg['To'] = ", ".join(self.config['message']['recipients'])
        msg['Subject'] = Header(self.config['message']['subject'], 'utf-8')


        msg.attach(MIMEText(self.text_content, 'plain', 'utf-8'))


        if self.has_attachments:
            self.attach_files(msg)

        return msg

    @property
    def has_attachments(self) -> bool:
        return bool(self.config['message']['attachments'].get('files'))

    def attach_files(self, msg: MIMEMultipart):
        folder = self.config['message']['attachments'].get('folder', 'attachments')

        for filename in self.config['message']['attachments']['files']:
            filepath = os.path.join(folder, filename)
            if not os.path.exists(filepath):
                print(f"файл не найден: {filepath}")
                continue

            mime_type, _ = mimetypes.guess_type(filepath)
            if mime_type is None:
                mime_type = 'application/octet-stream'

            main_type, sub_type = mime_type.split('/', 1)

            with open(filepath, 'rb') as f:
                part = MIMEApplication(
                    f.read(),
                    _subtype=sub_type
                )

            part.add_header(
                'Content-Disposition',
                'attachment',
                filename=Header(filename, 'utf-8').encode()
            )
            msg.attach(part)


if __name__ == "__main__":
    try:
        sender = SMTPSender()
        sender.send_email()
    except Exception as e:
        print(f"ошибка: {str(e)}")