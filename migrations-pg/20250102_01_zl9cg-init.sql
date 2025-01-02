-- init
-- depends: 

CREATE TABLE IF NOT EXISTS users(
    telegram_id             text PRIMARY KEY,

    samoware_login          text NOT NULL,
    samoware_password       text,
    samoware_cookies        text NOT NULL,
    samoware_session        text NOT NULL,
    samoware_ack_seq        int NOT NULL,
    samoware_request_id     int NOT NULL,
    samoware_command_id     int NOT NULL,
    samoware_rand           int NOT NULL,

    last_revalidation       timestamp with time zone NOT NULL,
    autoread                boolean NOT NULL DEFAULT false
);
