import os
from dotenv import load_dotenv

load_dotenv(".env", override=True)


def get_var_or_throw(var_name) -> str:
    if var_name not in os.environ:
        raise EnvironmentError(f"{var_name} env var does not exist")
    return os.environ.get(var_name)


def get_var_or_default(var_name: str, default: any) -> any:
    return os.environ.get(var_name, default=default)


def get_profile() -> str:
    return get_var_or_default("ENV", "unknown")


def get_version() -> str:
    return get_var_or_default("VERSION", "none")


def get_telegram_token() -> str:
    return get_var_or_throw("TELEGRAM_TOKEN")


def get_encryption_key() -> str | None:
    return get_var_or_default("ENCRYPTION", None)


def get_prometheus_metrics_server_port() -> int:
    return int(get_var_or_default("PROMETHEUS_METRICS_SERVER_PORT", 53000))


def get_postgres_db() -> str:
    return get_var_or_throw("POSTGRES_DB")


def get_postgres_user() -> str:
    return get_var_or_throw("POSTGRES_USER")


def get_postgres_password() -> str:
    return get_var_or_throw("POSTGRES_PASSWORD")


def get_postgres_host() -> str:
    return get_var_or_throw("POSTGRES_HOST")


def get_postgres_connections_count() -> str:
    return int(get_var_or_default("POSTGRES_CONNECTIONS_COUNT", 4))


def get_postgres_connection_string() -> str:
    return "postgresql://{}:{}@{}/{}".format(
        get_postgres_user(),
        get_postgres_password(),
        get_postgres_host(),
        get_postgres_db(),
    )


def get_healthcheck_server_port() -> int | None:
    port = get_var_or_default("HEALTHCHECK_SERVER_PORT", None)
    return int(port) if port is not None else None


def is_ip_check_enabled() -> bool:
    return get_var_or_default("IP_CHECK", None) is not None


def is_dev_profile() -> bool:
    return get_profile() == "DEV"


def is_prod_profile() -> bool:
    return get_profile() == "PROD"


def is_debug() -> bool:
    return get_var_or_default("DEBUG", None) is not None


def is_prometheus_metrics_server_enabled() -> bool:
    return get_var_or_default("ENABLE_PROMETHEUS_METRICS_SERVER", None) is not None

def get_browser_name() -> str:
    return get_var_or_default("ENV", "Firefox 145")
