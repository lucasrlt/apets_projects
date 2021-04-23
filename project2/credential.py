"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple
# from petrelic.multiplicative.pairing import G1, G2, GT
from random import randint

from serialization import jsonpickle
from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G2, GT
from binascii import hexlify

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Any  # a tuple (x, X, y1, ..., yL)
PublicKey = Any
Signature = Any
Attribute = Any
AttributeMap = Any
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    L = len(attributes)
    p = G1.order()
    x = p.random()
    ys = [0 for _ in range(L)]
    for i in range(L):
        ys[i] = p.random()
    g1 = G1.generator()
    g2 = G2.generator()
    X1 = g1 ** x
    X2 = g2 ** x
    Y1s = [0 for _ in range(L)]
    Y2s = [0 for _ in range(L)]
    for i in range(L):
        Y1s[i] = g1 ** ys[i]
        Y2s[i] = g2 ** ys[i]

    sk_list = [0 for _ in range(L + 2)]
    sk_list[0] = x
    sk_list[1] = X1
    for i in range(L):
        sk_list[i + 2] = ys[i]
    sk: SecretKey = tuple(sk_list)
    pk_list = [0 for _ in range(2 * L + 2)]
    pk_list[0] = g1
    pk_list[L + 1] = g2
    pk_list[L + 2] = X2
    for i in range(L):
        pk_list[i + 1] = Y1s[i]
        pk_list[i + L + 2] = Y2s[i]
    pk: PublicKey = tuple(pk_list)
    return (sk, pk)
    # raise NotImplementedError()


def sign(
        sk: SecretKey,
        msgs: List[bytes]
) -> Signature:
    """ Sign the vector of messages `msgs` """
    h = G1.generator()  # note: should be G1*

    exponent = sk[0]
    for idx, msg in enumerate(msgs):
        exponent += sk[2 + idx] * Bn.from_binary(msg).mod(G1.order())
    signature = (h, h ** (exponent))

    return signature


def test():
    msgs = [b"hello", b"coucou"]
    sk, pk = generate_key(msgs)
    print(sign(sk, msgs))

def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
) -> bool:
    """ Verify the signature on a vector of messages """
    X1 = pk[len(msgs)+2]
    product = 1
    for i in range(len(msgs)):
        product *= pk[i+1]**G1.hash_to_point(msgs[i])
    return signature[0] != pk[0].neutral_element() \
    and signature[0].pair(X1*product) == signature[1].pair(pk[len(msgs) + 1])


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    raise NotImplementedError()


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    raise NotImplementedError()


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    raise NotImplementedError()


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
) -> DisclosureProof:
    """ Create a disclosure proof """
    raise NotImplementedError()


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()
