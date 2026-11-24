"""OS-level enforcement primitives.

Each enforcer reports its real capability on the current host and never claims an
action it cannot perform — a ``block`` that the OS cannot pre-empt is surfaced as
``detect_only`` rather than a false 'prevented'.
"""
