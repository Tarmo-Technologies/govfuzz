# SPDX-License-Identifier: Apache-2.0
"""Campaign 2026-07-03 Python guards: a doctest example, a function parameter
default, and a call keyword argument are not hardcoded-secret assignments."""


def login(user, password="defaultpw"):
    """Log in.

    >>> login("alice", password="secret123")   # doctest, not code
    """
    client.connect(password="hunter2xyz")       # kwarg, not an assignment
    return user


API_TOKEN = "ghp_realtokenvalue12345"           # EXPECT GF-429

import random

csrf_token = random.randint(0, 999999)          # EXPECT GF-428
retry_delay = random.random()                   # safe: no security context
