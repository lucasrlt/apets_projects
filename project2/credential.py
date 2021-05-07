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

from petrelic.bn import Bn
from petrelic.multiplicative.pairing import G1, G1Element, G2, G2Element, GT

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
# SecretKey = Any  # a tuple (x, X, y1, ..., yL)
# PublicKey = Any
#TODO: verify all types are consistent with there actuel use (in functions)
Signature = Any #TODO: class as pk and sk?
Attribute = bytes #TODO: str instead?
AttributeMap = {int, Attribute} #TODO: maybe {str, attr_value} instead makes more sense?
IssueRequest = G1Element
BlindSignature = Tuple[G1Element]
AnonymousCredential = Tuple[G1Element]
DisclosureProof = Any #TODO: class as pk and sk?


class PublicKey:
    def __init__(self, g1: G1Element, Y1: List[G1Element], g2: G2Element, X2: G2Element, Y2: List[G2Element]):
        self.g1 = g1
        self.Y1 = Y1
        self.g2 = g2
        self.X2 = X2
        self.Y2 = Y2

class SecretKey:
    def __init__(self, x: Bn, X1: G1Element, y: List[int]):
        self.x = x
        self.X1 = X1
        self.y = y

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
    # sk: SecretKey = tuple(sk_list)

    sk: SecretKey = SecretKey(x, X1, ys)

    pk_list = [0 for _ in range(2 * L + 3)]
    pk_list[0] = g1
    pk_list[L + 1] = g2
    pk_list[L + 2] = X2
    for i in range(L):
        pk_list[i + 1] = Y1s[i]
        pk_list[i + L + 3] = Y2s[i]
    
    # pk: PublicKey = tuple(pk_list)
    pk = PublicKey(g1, Y1s, g2, X2, Y2s)

    return (sk, pk)
    # raise NotImplementedError()


def sign(
        sk: SecretKey,
        msgs: List[bytes]
) -> Signature: #TODO: remove this function? (especially if not tested/ not correct) but maybe useful for testing though
    """ Sign the vector of messages `msgs` """
    h = G1.generator()  # note: should be G1*

    exponent = sk[0]
    for idx, msg in enumerate(msgs):
        exponent += sk[2 + idx] * Bn.from_binary(msg).mod(G1.order())
    signature = (h, h ** (exponent))

    return signature

def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
) -> bool:
    """ Verify the signature on a vector of messages """
    product = pk.X2
    for i in range(len(msgs)):
        product *= pk.Y2[i] **Bn.from_binary(msgs[i])

    return signature[0] != G2.neutral_element() and signature[0].pair(product) == signature[1].pair(pk.g2)