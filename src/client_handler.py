import asyncio
import logging as log
from datetime import datetime, timedelta, timezone
import re
from typing import Self
import hashlib
import aiohttp

from context import Context
from infra.ratelimiter import RateLimiter, RateException

from const import (
    HTML_FORMAT,
    HTTP_RETRY_DELAY_SEC,
    MARKDOWN_FORMAT,
)
from database import Database
import samoware_api
from samoware_api import Mail, UnauthorizedError, ChangePasswordError
from util import MessageSender
from metrics import (
    event_metric,
    user_handler_error_metric,
)

REVALIDATION_INTERVAL = timedelta(hours=5)
SESSION_TOKEN_PATTERN = re.compile("^[0-9]{6}-[a-zA-Z0-9]{20}$")

MAX_LOGIN_ATTEMPTS = 3
LOGIN_PERIOD = timedelta(minutes=2)

SUCCESSFUL_LOGIN_PROMPT = (
    "Доступ выдан. Все новые письма будут пересылаться в этот чат."
)
CAN_NOT_REVALIDATE_PROMPT = "Невозможно продлить сессию из-за внутренней ошибки. Для продолжения работы необходима повторная авторизация\n/login _логин_ _пароль_"
SESSION_EXPIRED_PROMPT = "Сессия доступа к почте истекла. Для продолжения работы необходима повторная авторизация\n/login _логин_ _пароль_"
CAN_NOT_RELOGIN_PROMPT = "Ошибка при автоматической повторной авторизации, невозможно продлить сессию. Для продолжения работы необходима авторизация\n/login _логин_ _пароль_"
CAN_NOT_RELOGIN_CHANGE_PASSWORD_PROMPT = "Получено сообщение от почтового сервера. Необходимо сменить пароль. Работа бота приостановлена. Для продолжения работы смените пароль (https://student.bmstu.ru) и заново авторизуйтесь\n/login _логин_ _пароль_"
WRONG_CREDS_PROMPT = "Неверный логин или пароль."
CHANGE_PASSWORD_PROMPT = "Сервер Бауманской почты требует сменить пароль: https://student.bmstu.ru\n\nСмените пароль, после чего выполните авторизацию заново."
UNKNOWN_LOGIN_ERROR_PROMPT = "Неизвестная ошибка авторизации"
HANDLER_IS_ALREADY_WORKED_PROMPT = "Доступ уже был выдан."
LOGIN_LIMITED_PROMPT = (
    "Превышено допустимое количество попыток входа. Попробуйте еще раз через {} сек."
)


class AuthResult:
    OK = 0
    UNAUTHORIZED = 1
    CHANGE_PASSWORD = 2
    UNKNOWN_ERROR = 3


login_ratelimiters = {}


def check_ratelimiter(telegram_id: int):
    if telegram_id not in login_ratelimiters:
        login_ratelimiters[telegram_id] = RateLimiter(MAX_LOGIN_ATTEMPTS, LOGIN_PERIOD)
    login_ratelimiters[telegram_id].check()


class UserHandler:
    def __init__(
        self,
        message_sender: MessageSender,
        db: Database,
        context: Context,
    ):
        self.message_sender = message_sender
        self.db = db
        self.context = context
        self.revalidation_delta = self.make_user_based_revalidation_delta()

    @classmethod
    async def make_new(
        cls,
        telegram_id: int,
        samoware_login: str,
        samoware_password: str,
        message_sender: MessageSender,
        db: Database,
    ) -> Self | None:
        if await db.is_user_active(telegram_id):
            await message_sender(
                telegram_id, HANDLER_IS_ALREADY_WORKED_PROMPT, MARKDOWN_FORMAT
            )
            return None

        try:
            check_ratelimiter(telegram_id)
        except RateException as e:
            await message_sender(
                telegram_id,
                LOGIN_LIMITED_PROMPT.format(e.timeout.seconds),
                MARKDOWN_FORMAT,
            )
            return None

        handler = UserHandler(message_sender, db, Context(telegram_id, samoware_login))
        login_result = await handler.login(samoware_password)
        event_metric.labels(
            event_name=f"login {"suc" if (login_result == AuthResult.OK) else "unsuc"}"
        ).inc()
        if login_result == AuthResult.UNAUTHORIZED:
            await message_sender(telegram_id, WRONG_CREDS_PROMPT, MARKDOWN_FORMAT)
            return None
        elif login_result == AuthResult.CHANGE_PASSWORD:
            await message_sender(telegram_id, CHANGE_PASSWORD_PROMPT, MARKDOWN_FORMAT)
            return None
        elif login_result != AuthResult.OK:
            await message_sender(
                telegram_id, UNKNOWN_LOGIN_ERROR_PROMPT, MARKDOWN_FORMAT
            )
            return None
        await db.add_user(telegram_id, handler.context)
        await message_sender(telegram_id, SUCCESSFUL_LOGIN_PROMPT, MARKDOWN_FORMAT)
        return handler

    @classmethod
    async def make_from_context(
        cls, context: Context, message_sender: MessageSender, db: Database
    ) -> Self:
        return UserHandler(message_sender, db, context)

    async def start_handling(self) -> asyncio.Task:
        self.polling_task = asyncio.create_task(self.polling())
        return self.polling_task

    def get_polling_task(self) -> asyncio.Task:
        return self.polling_task

    async def stop_handling(self) -> None:
        if not (self.polling_task.cancelled() or self.polling_task.done()):
            self.polling_task.cancel()
            event_metric.labels(event_name="logout").inc()
        await asyncio.wait([self.polling_task])

    async def polling(self) -> None:
        try:
            retry_count = 0
            log.info(f"longpolling for {self.context.samoware_login} is started")

            while await self.db.is_user_active(self.context.telegram_id):
                try:
                    polling_context = self.context.polling_context
                    await self.db.set_handler_context(self.context)
                    (polling_result, polling_context) = (
                        await samoware_api.longpoll_updates(polling_context)
                    )
                    if samoware_api.has_updates(polling_result):
                        (mails, polling_context) = await samoware_api.get_new_mails(
                            polling_context
                        )
                        for mail_header in mails:
                            event_metric.labels(event_name="incoming letter").inc()
                            log.info(f"new mail for {self.context.samoware_login}")
                            log.debug(f"email flags: {mail_header.flags}")
                            mail_body = await samoware_api.get_mail_body_by_id(
                                polling_context, mail_header.uid
                            )
                            await self.forward_mail(Mail(mail_header, mail_body))
                            if await self.db.get_autoread(self.context.telegram_id):
                                polling_context = await samoware_api.mark_as_read(
                                    polling_context, mail_header.uid
                                )
                    self.context.polling_context = polling_context
                    revalidation_result = await self.check_revalidation()
                    if revalidation_result != AuthResult.OK:
                        log.warning(
                            f"cannot revalidate user {self.context.samoware_login}"
                        )
                        if revalidation_result == AuthResult.CHANGE_PASSWORD:
                            await self.can_not_relogin_change_password()
                            await self.db.remove_user(self.context.telegram_id)
                            event_metric.labels(event_name="forced logout").inc()
                            return
                    retry_count = 0
                except asyncio.CancelledError:
                    return
                except UnauthorizedError as error:
                    user_handler_error_metric.labels(type=type(error).__name__).inc()
                    log.info(f"session for {self.context.samoware_login} expired")
                    samoware_password = await self.db.get_password(
                        self.context.telegram_id
                    )
                    if samoware_password is None:
                        await self.session_has_expired()
                        await self.db.remove_user(self.context.telegram_id)
                        event_metric.labels(event_name="forced logout").inc()
                        return
                    relogin_result = await self.login(samoware_password)
                    event_metric.labels(
                        event_name=f"relogin {"suc" if (relogin_result == AuthResult.OK) else "unsuc"}"
                    ).inc()
                    if relogin_result != AuthResult.OK:
                        await self.can_not_relogin()
                        await self.db.remove_user(self.context.telegram_id)
                        event_metric.labels(event_name="forced logout").inc()
                        return
                except (
                    aiohttp.ClientOSError
                ) as error:  # unknown source error https://github.com/aio-libs/aiohttp/issues/6912
                    log.warning(
                        f"retry_count={retry_count}. ClientOSError. Probably Broken pipe. Retrying in {HTTP_RETRY_DELAY_SEC} seconds. {str(error)}"
                    )
                    user_handler_error_metric.labels(type=type(error).__name__).inc()
                    retry_count += 1
                    await asyncio.sleep(HTTP_RETRY_DELAY_SEC)
                except Exception as error:
                    log.exception("exception in user_handler")
                    log.warning(
                        f"retry_count={retry_count}. Retrying longpolling for {self.context.samoware_login} in {HTTP_RETRY_DELAY_SEC} seconds..."
                    )
                    user_handler_error_metric.labels(type=type(error).__name__).inc()
                    retry_count += 1
                    await asyncio.sleep(HTTP_RETRY_DELAY_SEC)
        finally:
            log.info(f"longpolling for {self.context.samoware_login} stopped")

    async def login(self, samoware_password: str) -> AuthResult:
        log.debug("trying to login")
        retry_count = 0
        while True:
            try:
                polling_context = await samoware_api.login(
                    self.context.samoware_login, samoware_password
                )
                polling_context = await samoware_api.set_session_info(polling_context)
                polling_context = await samoware_api.open_inbox(polling_context)
                self.context.polling_context = polling_context
                self.context.last_revalidation = datetime.now(timezone.utc)
                await self.db.set_handler_context(self.context)
                log.info(f"successful login for user {self.context.samoware_login}")
                return AuthResult.OK
            except UnauthorizedError as error:
                log.info(f"unsuccessful login for user {self.context.samoware_login}")
                user_handler_error_metric.labels(type=type(error).__name__).inc()
                return AuthResult.UNAUTHORIZED
            except ChangePasswordError as error:
                log.info(f"user {self.context.samoware_login} needs to change password")
                user_handler_error_metric.labels(type=type(error).__name__).inc()
                return AuthResult.CHANGE_PASSWORD
            except asyncio.CancelledError:
                log.info("login cancelled")
                return AuthResult.UNKNOWN_ERROR
            except Exception as error:
                log.exception(
                    f"retry_count={retry_count}. exception on login. retrying in {HTTP_RETRY_DELAY_SEC}..."
                )
                user_handler_error_metric.labels(type=type(error).__name__).inc()
                retry_count += 1
                await asyncio.sleep(HTTP_RETRY_DELAY_SEC)

    async def check_revalidation(self) -> AuthResult:
        if datetime.astimezone(
            self.context.last_revalidation + self.revalidation_delta,
            timezone.utc,
        ) < datetime.now(timezone.utc):
            revalidation_result = await self.revalidate()
            event_metric.labels(
                event_name=f"revalidation {"suc" if (revalidation_result == AuthResult.OK) else "unsuc"}"
            ).inc()
            return revalidation_result
        return AuthResult.OK

    async def revalidate(self) -> AuthResult:
        log.debug("trying to revalidate")
        try:
            polling_context = await samoware_api.revalidate(
                self.context.samoware_login, self.context.polling_context.session
            )
            if polling_context is None:
                log.info(
                    f"unsuccessful revalidation for user {self.context.samoware_login}"
                )
                return False
            polling_context = await samoware_api.set_session_info(polling_context)
            polling_context = await samoware_api.open_inbox(polling_context)
            self.context.polling_context = polling_context
            self.context.last_revalidation = datetime.now(timezone.utc)
            await self.db.set_handler_context(self.context)
            log.info(f"successful revalidation for user {self.context.samoware_login}")
            return AuthResult.OK
        except UnauthorizedError as error:
            log.exception("UnauthorizedError on revalidation")
            user_handler_error_metric.labels(type=type(error).__name__).inc()
            return AuthResult.UNAUTHORIZED
        except ChangePasswordError as error:
            log.info(f"user {self.context.samoware_login} needs to change password")
            user_handler_error_metric.labels(type=type(error).__name__).inc()
            return AuthResult.CHANGE_PASSWORD

    async def can_not_revalidate(self):
        await self.message_sender(
            self.context.telegram_id,
            CAN_NOT_REVALIDATE_PROMPT,
            MARKDOWN_FORMAT,
        )

    async def can_not_relogin(self):
        await self.message_sender(
            self.context.telegram_id, CAN_NOT_RELOGIN_PROMPT, MARKDOWN_FORMAT
        )

    async def can_not_relogin_change_password(self):
        await self.message_sender(
            self.context.telegram_id,
            CAN_NOT_RELOGIN_CHANGE_PASSWORD_PROMPT,
            MARKDOWN_FORMAT,
        )

    async def session_has_expired(self):
        await self.message_sender(
            self.context.telegram_id,
            SESSION_EXPIRED_PROMPT,
            MARKDOWN_FORMAT,
        )

    async def forward_mail(self, mail: Mail):
        from_str = f'<a href="copy-this-mail.example/{mail.header.from_mail}">{mail.header.from_name}</a>'
        to_str = ", ".join(
            f'<a href="copy-this-mail.example/{recipient[0]}">{recipient[1]}</a>'
            for recipient in mail.header.recipients
        )

        mail_text = f'{datetime.strftime(mail.header.local_time, "%d.%m.%Y %H:%M")}\n\nОт кого: {from_str}\n\nКому: {to_str}\n\n<b>{mail.header.subject}</b>\n\n{mail.body.text}'

        asyncio.create_task(
            self.message_sender(
                self.context.telegram_id,
                mail_text,
                HTML_FORMAT,
                mail.body.attachments if len(mail.body.attachments) > 0 else None,
            )
        )

    def make_user_based_revalidation_delta(self):
        """
        Для каждого пользователя интервал ревалидации свой,
        чтобы размазать нагрузку по ревалидации во времени.
        Для каждого пользователя дельта для ревалидации составляет от 4.5 до 5 часов.
        """
        hash_key = str(self.context.telegram_id) + self.context.samoware_login
        interval = 30
        diff = (
            -interval
            + int(hashlib.sha256(hash_key.encode("utf-8")).hexdigest(), 16) % interval
        )
        revalidation_interval = REVALIDATION_INTERVAL + timedelta(minutes=diff)
        log.debug(
            f"setting revalidation shift for user {self.context.telegram_id} for {revalidation_interval}"
        )
        return revalidation_interval
