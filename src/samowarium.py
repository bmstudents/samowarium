#!/bin/python3

import logging.handlers
from telegram_bot import TelegramBot
from prometheus_client import start_http_server
import asyncio

import logging
import signal

from metrics import GATHER_METRIC_DELAY_SEC, users_amount_metric, log_metric
from const import LOGGER_FOLDER_PATH, LOGGER_PATH
from database import Database
from encryption import Encrypter
import env
import util
import healthcheck


class Application:
    async def start(self) -> None:
        self.encrypter = Encrypter()
        self.db = Database(self.encrypter)
        await self.db.open()
        self.bot = TelegramBot(self.db)
        await self.bot.start_bot()
        self.gathering_metric_task = asyncio.create_task(
            self.gather_users_amount_metric()
        )
        self.setupShutdown(asyncio.get_event_loop())

    def setupShutdown(self, event_loop: asyncio.AbstractEventLoop):
        async def shutdown(signal) -> None:
            logging.info(f"received exit signal {signal}")
            self.gathering_metric_task.cancel()
            await self.bot.stop_bot()
            await self.db.close()
            logging.info("application has stopped successfully")

        for s in (signal.SIGHUP, signal.SIGTERM, signal.SIGINT):
            event_loop.add_signal_handler(
                s, lambda s=s: asyncio.create_task(shutdown(s))
            )

    async def gather_users_amount_metric(self):
        try:
            while self.db.is_open():
                users = await self.db.get_all_users_stat()
                for pswd, autoread in (
                    (x, y) for x in (True, False) for y in (True, False)
                ):
                    users_amount_metric.labels(pswd=pswd, autoread=autoread).set(
                        len(
                            list(
                                filter(
                                    lambda x: x[0] == pswd and x[1] == autoread, users
                                )
                            )
                        )
                    )
                await asyncio.sleep(GATHER_METRIC_DELAY_SEC)
        except:
            pass


def setup_logger():
    LOGGER_LEVEL = logging.INFO
    if env.is_debug():
        LOGGER_LEVEL = logging.DEBUG
    util.make_dir_if_not_exist(LOGGER_FOLDER_PATH)
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        filename=LOGGER_PATH,
        encoding="utf-8",
        level=LOGGER_LEVEL,
    )
    logging.getLogger("httpx").setLevel(logging.WARN)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    if env.is_prod_profile():
        logging.getLogger("telegram.ext.Updater").setLevel(logging.CRITICAL)

    class MetricsHandler(logging.Handler):
        def emit(self, record):
            log_metric.labels(level=record.levelname).inc()

    logging.getLogger("root").addHandler(MetricsHandler())


async def main() -> None:
    setup_logger()

    if env.is_prometheus_metrics_server_enabled():
        port = env.get_prometheus_metrics_server_port()
        logging.info(f"starting the metrics server on {port} port...")
        start_http_server(port)
    logging.info("starting the application...")

    app = Application()
    await app.start()

    if (port := env.get_healthcheck_server_port()) is not None:
        logging.info(f"starting healthcheck server on {port} port...")
        await healthcheck.setup_healtcheck_server(port)

    await asyncio.gather(
        *[task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    )


if __name__ == "__main__":
    asyncio.run(main())
