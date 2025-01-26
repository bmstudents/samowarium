from aiohttp import web
import asyncio


async def setup_healtcheck_server(port: int):
    app = web.Application()
    app.add_routes([web.get("/", healthcheck_endpoint)])
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="localhost", port=port)
    asyncio.create_task(site.start())


async def healthcheck_endpoint(_: web.Request):
    return web.Response(status=200)
