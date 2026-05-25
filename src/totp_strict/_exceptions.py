"""Custom exceptions for totp-strict security guards."""


class TOTPStrictError(Exception):
    """Base exception for all totp-strict errors."""


class RateLimitExceeded(TOTPStrictError):
    """Raised when a user has exceeded the maximum number of failed
    verification attempts and is temporarily locked out.

    Attributes:
        user_id:         The identifier of the locked-out user.
        retry_after:     Seconds remaining until the lockout expires.
    """

    def __init__(self, user_id: str, retry_after: float) -> None:
        self.user_id = user_id
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded for user {user_id!r}. "
            f"Retry after {retry_after:.0f}s."
        )


class CodeAlreadyUsed(TOTPStrictError):
    """Raised when a TOTP code has already been successfully verified
    within its validity window — indicating a potential replay attack.

    Attributes:
        user_id:  The identifier of the user.
    """

    def __init__(self, user_id: str) -> None:
        self.user_id = user_id
        super().__init__(
            f"Code already used for user {user_id!r}. "
            "Possible replay attack."
        )
