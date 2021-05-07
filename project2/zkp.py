import hashlib
from typing import Any, List
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT
import serialization
import jsonpickle


def get_challenge(R: Bn, generators: List[Any], commitment: Bn, message: bytes):
    sha256 = hashlib.sha256()
    # print(str(R))
    # print(jsonpickle.encode(R).encode())
    sha256.update(jsonpickle.encode(R).encode())
    sha256.update(jsonpickle.encode(commitment).encode())
    sha256.update(message)
    for g in generators:
        sha256.update(jsonpickle.encode(g).encode())
    return int.from_bytes(sha256.digest(), 'big')


def pedersen_commitment(secrets, generators, commitment, message=b"", group=G1):
    rs = [group.order().random() for _ in range(len(secrets))]

    R = group.neutral_element()
    for i, r in enumerate(rs):
        R *= generators[i] ** r

    challenge = get_challenge(R, generators, commitment, message)

    ss = [None for _ in secrets]
    for i, r in enumerate(rs):
        ss[i] = (r - challenge * secrets[i])

    # print("Wesh", ss)
    return challenge, ss


def verify_petersen(c, ss, generators, commitment, message=b""):
    R = commitment ** c
    for i, s in enumerate(ss):
        R *= generators[i] ** s

    c_prime = get_challenge(R, generators, commitment, message)

    return c_prime == c