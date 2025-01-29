from telegram import Update, InputMediaDocument
import telegram
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
import logging as log
from typing import Optional
import asyncio
from client_handler import UserHandler
from const import MARKDOWN_FORMAT, MARKDOWN_FORMAT_V2, TELEGRAM_SEND_RETRY_DELAY_SEC
from database import Database
import env
import metrics
import re

START_PROMPT = "Выдать доступ боту до почты :\n/login _логин_ _пароль_\n\nОтозвать доступ:\n/stop\n\nFAQ:\n/about"
STOP_PROMPT = "Доступ отозван. Логин и сессия были удалены."
ABOUT_PROMPT = """
Samowarium - бот, который пересылает входящие письма в личные сообщения телеграм.

Список команд бота:
/login - выдать боту доступ к почтовому серверу;
/stop - отозвать доступ и удалить информацию о пользователе;
/about - получить дополнительную информацию.

Есть вопрос, предложение или сообщение об ошибке?
Напиши нам в чате поддержки: [тык](https://t.me/+Myl1sMnhbdM5M2Ji)!

Как работает бот?
При передаче пары логин/пароль бот получает от почтового сервера токен сессии, с помощью которого в дальнейшем обрабатывает входящие письма.
Если пользователь выбрал опцию "не сохранять пароль", то бот его забывает после получения сессии почтового сервера. В ином случае бот запоминает пароль пользователя.
Токен сессии почтового сервера возможно использовать только для работы с почтой, бот не может с помощью него получить доступ к остальным сервисам МГТУ.

Как хранятся пароли?
Пароли пользователей хранятся в защищенной базе данных.
Каждый пароль хранится в базе данных в зашифрованном виде и расшифровывается только при необходимости пройти реавторизацию. Шифрование осуществляется алгоритмом AES256.

Зачем хранить пароли?
Токены сессии почтового сервера имеют весьма короткий срок жизни. При отсутствии обращений на почтовый сервер токен становится недействительным в течение 3-5 минут. Бауманский почтовый сервер не имеет необходимый уровень доступности и периодически становится недоступен на промежутки времени, большие 5 минут. После таких периодов недоступности все активные сессии становятся недействительны, и требуют повторной авторизации. Для выполнения повторной авторизации в автоматическом режиме бот может использовать запомненные пароли пользователей.

Как удалить свои данные из бота?
Для удаления данных о пользователе можно воспользоваться командой /stop

Репозиторий проекта: [GitHub](https://github.com/bmstudents/samowarium)

Версия: `{}-{}`
"""
LOGIN_WRONG_FORMAT_PROMPT = (
    "Неверный формат использования команды:\n/login _логин_ _пароль_"
)
HANDLER_IS_ALREADY_SHUTTED_DOWN_PROMPT = "Доступ уже был отозван."
WAIT_TO_AUTH_PROMPT = "Авторизация. Пожалуйста, подождите..."
SAVE_PASSWORD_PROMPT = (
    "Сохранить пароль? Подробнее о хранении и использовании паролей: /about"
)
PASSWORD_SAVED_PROMPT = "Пароль сохранен."

AUTOREAD_PROMPT = (
    "Автоматически отмечать приходящие письма прочитанными? Выключено по умолчанию."
)
AUTOREAD_ON_PROMPT = "Письма будут отмечаться прочитанными автоматически."
AUTOREAD_OFF_PROMPT = "Письма не будут отмечаться прочитанными."

MAX_TELEGRAM_MESSAGE_LENGTH = 4096

HTTP_FILE_SEND_TIMEOUT_SEC = 60

SAVE_PSW_CALLBACK = "SAVE_PSW"
NO_SAVE_PSW_CALLBACK = "NO_SAVE_PSW"

AUTOREAD_ON_CALLBACK = "AUTOREAD_ON"
AUTOREAD_OFF_CALLBACK = "AUTOREAD_OFF"


class TelegramBot:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.commands = [
            ("start", self.start_command),
            ("stop", self.stop_command),
            ("login", self.login_command),
            ("about", self.about_command),
        ]
        self.handlers: dict[int, UserHandler] = {}

    async def callback_query_handler(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ):
        data = update.callback_query.data.split(":")
        command = data[0]
        if command == SAVE_PSW_CALLBACK:
            password = data[1]
            await self.db.set_password(update.effective_user.id, password)
            await self.send_message(
                update.effective_user.id, PASSWORD_SAVED_PROMPT, MARKDOWN_FORMAT
            )
            log.info(f"password for user {update.effective_user.id} is saved")
        elif command == NO_SAVE_PSW_CALLBACK:
            log.info(f"password for user {update.effective_user.id} is not saved")
        elif command == AUTOREAD_ON_CALLBACK:
            await self.db.set_autoread(update.effective_user.id, True)
            await self.send_message(
                update.effective_user.id, AUTOREAD_ON_PROMPT, MARKDOWN_FORMAT
            )
            log.info(f"autoread for user {update.effective_user.id} is enabled")
        elif command == AUTOREAD_OFF_CALLBACK:
            await self.db.set_autoread(update.effective_user.id, False)
            await self.send_message(
                update.effective_user.id, AUTOREAD_OFF_PROMPT, MARKDOWN_FORMAT
            )
            log.info(f"autoread for user {update.effective_user.id} is not enabled")
        await self.application.bot.delete_message(
            update.effective_chat.id, update.callback_query.message.message_id
        )

    async def start_bot(self) -> None:
        log.info("starting the bot...")
        log.info("loading handlers...")
        for context in await self.db.get_all_users():
            handler = await UserHandler.make_from_context(
                context, self.send_message, self.db
            )
            await handler.start_handling()
            self.handlers[context.telegram_id] = handler
        log.info("handlers are loaded")

        log.info("connecting to telegram api...")
        self.application = Application.builder().token(env.get_telegram_token()).build()

        for command, handler in self.commands:
            self.application.add_handler(CommandHandler(command, handler))
        self.application.add_handler(CallbackQueryHandler(self.callback_query_handler))

        await self.application.initialize()
        await self.application.start()
        log.info("starting telegram polling...")
        await self.application.updater.start_polling()
        log.info("application is online")

    async def stop_bot(self):
        log.info("shutting down handlers...")
        await asyncio.gather(
            *[handler.stop_handling() for handler in self.handlers.values()]
        )
        log.info("shutting down the bot...")
        await self.application.updater.stop()
        await self.application.stop()
        await self.application.shutdown()
        log.info("telegram bot is shutted down")

    async def start_command(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        log.info(f"received /start from {update.effective_user.id}")
        metrics.incoming_commands_metric.labels(command_name="start").inc()
        await update.message.reply_markdown(START_PROMPT)

    async def stop_command(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        log.info(f"received /stop from {update.effective_user.id}")
        telegram_id = update.effective_user.id
        if telegram_id in self.handlers:
            await self.handlers[telegram_id].stop_handling()
            await self.db.remove_user(
                telegram_id
            )  # TODO: не удалять запись, а удалять только контекст и пароль
            metrics.incoming_commands_metric.labels(command_name="stop").inc()
            await update.message.reply_markdown(STOP_PROMPT)
        else:
            await update.message.reply_markdown(HANDLER_IS_ALREADY_SHUTTED_DOWN_PROMPT)

    async def login_command(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        log.info(f"received /login from {update.effective_user.id}")
        metrics.incoming_commands_metric.labels(command_name="login").inc()
        if context.args is None or len(context.args) != 2:
            log.info(
                f"user {update.effective_user.id} entered login and password in wrong format"
            )
            await update.message.reply_markdown(LOGIN_WRONG_FORMAT_PROMPT)
            return
        wait_message = await update.message.reply_markdown(WAIT_TO_AUTH_PROMPT)
        telegram_id = update.effective_user.id
        samoware_login = context.args[0]
        samoware_password = context.args[1]
        log.debug(f'user entered login "{samoware_login}" and password')
        new_handler = await UserHandler.make_new(
            telegram_id, samoware_login, samoware_password, self.send_message, self.db
        )
        if new_handler is not None:
            await new_handler.start_handling()
            self.handlers[telegram_id] = new_handler
            await self.application.bot.send_message(
                update.effective_chat.id,
                SAVE_PASSWORD_PROMPT,
                parse_mode=MARKDOWN_FORMAT,
                reply_markup=telegram.InlineKeyboardMarkup(
                    [
                        [
                            telegram.InlineKeyboardButton(
                                text="Да",
                                callback_data=":".join(
                                    (
                                        SAVE_PSW_CALLBACK,
                                        samoware_password,
                                    )
                                ),
                            ),
                            telegram.InlineKeyboardButton(
                                text="Нет",
                                callback_data=":".join((NO_SAVE_PSW_CALLBACK,)),
                            ),
                        ]
                    ]
                ),
            )
            await self.application.bot.send_message(
                update.effective_chat.id,
                AUTOREAD_PROMPT,
                parse_mode=MARKDOWN_FORMAT,
                reply_markup=telegram.InlineKeyboardMarkup(
                    [
                        [
                            telegram.InlineKeyboardButton(
                                text="Да", callback_data=AUTOREAD_ON_CALLBACK
                            ),
                            telegram.InlineKeyboardButton(
                                text="Нет",
                                callback_data=AUTOREAD_OFF_CALLBACK,
                            ),
                        ]
                    ]
                ),
            )
        await self.application.bot.delete_messages(
            update.effective_chat.id, [update.effective_message.id, wait_message.id]
        )

    async def about_command(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        metrics.incoming_commands_metric.labels(command_name="about").inc()
        await update.message.reply_markdown(
            ABOUT_PROMPT.format(env.get_profile(), env.get_version()),
            disable_web_page_preview=True,
        )

    async def send_message(
        self,
        telegram_id: int,
        message: str,
        format: str | None = None,
        attachments: Optional[list[tuple[bytes, str]]] = None,
    ) -> None:
        if format == MARKDOWN_FORMAT_V2:
            message = re.sub(r'[_*[\]()~>#\+\-=|{}.!]', lambda x: '\\' + x.group(), message)
            log.info(f"jopa {message}")
            message = re.sub(r'\\\\[_*[\]()~>#\+\-=|{}.!]', lambda x: x.group()[2:], message)
        log.info(f"jopa {message}")
        is_sent = False
        log.debug(f"sending a message to {telegram_id} ...")
        metrics.sent_message_metric.inc()
        while not is_sent:
            try:
                for shift in range(0, len(message), MAX_TELEGRAM_MESSAGE_LENGTH):
                    message_part = message[
                        shift : min(shift + MAX_TELEGRAM_MESSAGE_LENGTH, len(message))
                    ]
                    await self.application.bot.send_message(
                        telegram_id, message_part, parse_mode=format
                    )
                if attachments is not None:
                    await self.send_attachments(telegram_id, attachments)
                is_sent = True
                log.info(f"sent message to {telegram_id}")
            except telegram.error.Forbidden as error:
                log.exception("exception in send_message:\n" + str(error))
                log.info(f"User {telegram_id} is forbidden. Not retrying")
                self.db.remove_user(telegram_id)
                metrics.event_metric.labels(event_name="message for forbidden user").inc()
                break
            except telegram.error.BadRequest as error:
                log.warning(f"unsupported mail format for user {telegram_id}: {str(error)}")
                metrics.event_metric.labels(event_name="unsupported email message").inc()
                try:
                    message_header = "\n".join(message.split("\n")[0:6] + \
                                               ["\n_Отображение не поддерживается. Для просмотра письма используйте [почтовый клиент](https://student.bmstu.ru/)._"])
                    await self.application.bot.send_message(
                        telegram_id, message_header, parse_mode=format
                    )
                except Exception as error:
                    metrics.event_metric.labels(event_name="fail on unsupported mail").inc()
                    log.exception(f"cannot send message due bad request to user {telegram_id}")
                is_sent = True
            except Exception as error:
                log.exception("exception in send_message:\n" + str(error))
                metrics.event_metric.labels(event_name="fail on send").inc()
                log.info(
                    f"retrying to send message for {telegram_id} in {TELEGRAM_SEND_RETRY_DELAY_SEC} seconds..."
                )
                await asyncio.sleep(TELEGRAM_SEND_RETRY_DELAY_SEC)

    async def send_attachments(
        self, telegram_id: int, attachments: Optional[list[tuple[bytes, str]]]
    ):
        media_group = []
        for attachment in attachments:
            (file, name) = attachment
            media_group.append(InputMediaDocument(file, filename=name))
        sent = False
        log.debug(
            f"sending attachments ({[name for (_, name) in attachments]}) to {telegram_id} ..."
        )
        while not sent:
            try:
                await self.application.bot.send_media_group(
                    telegram_id,
                    media_group,
                    read_timeout=HTTP_FILE_SEND_TIMEOUT_SEC,
                    write_timeout=HTTP_FILE_SEND_TIMEOUT_SEC,
                )
                sent = True
                metrics.event_metric.labels(event_name="send attachment").inc()
                log.info(f"sent attachments to {telegram_id}")
            except telegram.error.BadRequest as error:
                log.exception("exception in send_attachments:\n" + str(error))
                log.info("error is bad request. Not retrying")
                break
            except Exception as error:
                log.exception("exception in send_attachments:\n" + str(error))
                log.info(
                    f"retrying to send attachments for {telegram_id} in {TELEGRAM_SEND_RETRY_DELAY_SEC} seconds..."
                )
                await asyncio.sleep(TELEGRAM_SEND_RETRY_DELAY_SEC)
