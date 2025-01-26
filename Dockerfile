FROM python:3.12-slim

RUN apt-get -y update && apt-get install -y --no-install-recommends libpq-dev build-essential curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /samowarium

COPY yoyo.ini .

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY ./migrations ./migrations
COPY ./src .

# port for prometheus metric server
EXPOSE 53000

# port for healthcheck server
ENV HEALTHCHECK_SERVER_PORT=53001

ENTRYPOINT [ "python3", "samowarium.py" ]
