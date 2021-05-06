import hashlib

import jsonpickle


def get_challenge(R, generators, commitment, message):
    sha256 = hashlib.sha256()
    sha256.update(jsonpickle.encode(R))
    sha256.update(jsonpickle.encode(commitment))
    sha256.update(message)
    for g in generators:
        sha256.update(jsonpickle.encode(g))
    return int.from_bytes(sha256.digest(), 'big')


def pedersen_commitment(secrets, generators, commitment, message, group=G1):
    rs = [group.order().random() for _ in range(len(secrets))]
    R = group.neutral_element()
    for i, r in enumerate(rs):
        R *= generators[i] ** r
    challenge = get_challenge(R, generators, commitment, message)
    ss = [0 for _ in range(secrets)]
    for i, r in enumerate(rs):
        ss[i] = (r - challenge * secrets[i]) % group.order()
    return challenge, ss


def verify_petersen(c, ss, generators, commitment, message=b''):
    R = commitment ** c
    for i, g in enumerate(generators):
        R *= g ** ss[i]
    c_prime = get_challenge(R, generators, commitment, message)
    return c_prime == c