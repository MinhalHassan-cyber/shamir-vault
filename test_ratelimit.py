from ratelimit import Lockout, RateLimiter


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_rate_limiter_blocks_then_recovers():
    c = Clock()
    rl = RateLimiter(3, 10, clock=c)
    assert [rl.allow("ip") for _ in range(4)] == [True, True, True, False]
    assert rl.allow("other")          # keys are independent
    c.t = 11
    assert rl.allow("ip")             # window has passed


def test_lockout_triggers_and_expires():
    c = Clock()
    lo = Lockout(3, 60, 120, clock=c)
    assert lo.record_failure("v") is False
    assert lo.record_failure("v") is False
    assert lo.record_failure("v") is True
    assert lo.is_locked("v")
    c.t = 119
    assert lo.is_locked("v")
    c.t = 121
    assert not lo.is_locked("v")


def test_lockout_forgets_old_failures():
    c = Clock()
    lo = Lockout(3, 60, 120, clock=c)
    lo.record_failure("v")
    lo.record_failure("v")
    c.t = 61
    assert lo.record_failure("v") is False
    assert not lo.is_locked("v")
