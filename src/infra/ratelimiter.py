from datetime import timedelta, datetime, timezone


class RateException(Exception):
    def __init__(self, timeout: timedelta):
        self.timeout = timeout


class RateLimiter:
    def __init__(self, max_calls: int, period: timedelta):
        self.max_calls = max_calls
        self.period = period

        self.calls = 0
        self.last_call_time = 0

    def check(self):
        now = datetime.now(timezone.utc).timestamp()
        if now - self.last_call_time >= self.period.seconds:
            self.calls = 0

        if self.calls < self.max_calls:
            self.calls += 1
            self.last_call_time = now
        else:
            timeout = timedelta(
                seconds=int(self.last_call_time + self.period.seconds - now)
            )
            raise RateException(timeout)
