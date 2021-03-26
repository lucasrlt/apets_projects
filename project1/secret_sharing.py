"""
Secret sharing scheme.
"""

from typing import List
from random import randint

class Share:
    """
    A secret share in a finite field.
    """

    def __init__(self, value: str):
        self.value = value

    def __repr__(self):
        return f"Share({self.value})"

    def __add__(self, other):
        return int(self.value) + int(other.value)

    def __sub__(self, other):
        return int(self.value) - int(other.value)

    def __mul__(self, other):
        return int(self.value) * int(other.value)


def share_secret(secret: int, num_shares: int) -> List[Share]:
    """Generate secret shares."""
    shares = []
    for i in range(num_shares - 1):
        shares.append(randint(1, secret - sum(shares) - num_shares + i))
    shares.append(secret - sum(shares))

    return shares


def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""
    sum = 0
    for share in shares:
        sum += int(share.value)
        
    return sum


# Feel free to add as many methods as you want.
