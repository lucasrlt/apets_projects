import hashlib
from typing import List

import jsonpickle

from credential import PublicKey, AttributeMap, IssueRequest, BlindSignature, AnonymousCredential, Attribute, verify, \
    DisclosureProof
from petrelic.multiplicative.pairing import G1, G2, GT, Bn, G1Element


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


class User:

    def __init__(self, disclosed_attributes: AttributeMap, hidden_attributes: AttributeMap):
        self.t = 0
        self.disclosed_attributes = disclosed_attributes
        self.hidden_attributes = hidden_attributes
        self.L = len(disclosed_attributes) + len(hidden_attributes)

        # Create a list of all attributes
        self.all_attributes = [None for _ in range(self.L)]
        for key in disclosed_attributes:
            self.all_attributes[key] = disclosed_attributes[key]
        for key in hidden_attributes:
            self.all_attributes[key] = hidden_attributes[key]

    ## ISSUANCE PROTOCOL ##

    def create_issue_request(
            self,
            pk: PublicKey,
            user_attributes: AttributeMap
    ) -> IssueRequest:
        """ Create an issuance request

        This corresponds to the "user commitment" step in the issuance protocol.

        *Warning:* You may need to pass state to the `obtain_credential` function.
        """
        self.t = G1.order().random()
        C = pk.g1 ** self.t
        for user_index in user_attributes:
            C *= pk.Y1[user_index] ** Bn.from_binary(user_attributes[user_index])
        # TODO: ZKP
        zkp = pedersen_commitment(self.hidden_attributes.items() + [self.t], pk.Y1 + [pk.g1], C)
        return C, zkp

    def obtain_credential(
            self,
            pk: PublicKey,
            response: BlindSignature
    ) -> AnonymousCredential:
        """ Derive a credential from the issuer's response

        This corresponds to the "Unblinding signature" step.
        """
        s = response[0], response[1] / (response[0] ** self.t)

        # reconstruct array of all attributes in order
        if verify(pk, s, self.all_attributes):
            return s
        else:
            return None

    ### SHOWING PROTOCOL
    def create_disclosure_proof(
            self,
            pk: PublicKey,
            credential: AnonymousCredential,
            message: bytes
    ) -> DisclosureProof:
        """ Create a disclosure proof """

        r = G1.order().random()
        t = G1.order().random()

        s = (credential[0] ** r, (credential[1] * credential[0] ** t) ** r)

        generators = []

        commitment = s[0].pair(pk.g2) ** t
        for i, ai in enumerate(self.hidden_attributes):
            generator = s[0].pair(pk.Y2[i])
            commitment *= generator ** ai
            generators.append(s[0].pair(pk.Y2[i]))

        # compute ZKP
        zkp = pedersen_commitment(self.hidden_attributes.items() + [self.t], generator + s[0].pair(pk.g2), commitment,
                                  b'', GT)

        return s, zkp, commitment

