from credential import generate_key
from petrelic.multiplicative.pairing import G1, G2, GT

from issuer import Issuer
from user import User


def test_gen_key():
    attributes = ["age", "name", "gender"]
    L = len(attributes)
    (sk, pk) = generate_key(attributes)
    g1 = pk[0]
    g2 = pk[L + 1]
    assert g1 == G1.generator()
    assert g2 == G2.generator()
    x = sk[0]
    assert 0 <= x < G1.order()
    X_1 = sk[1]
    assert g1 ** x == X_1
    X_2 = pk[L + 2]
    assert g2 ** x == X_2
    for i in range(L):
        y = sk[i + 2]
        Y_1 = pk[i + 1]
        Y_2 = pk[i + L + 3]
        assert 0 <= y < G1.order()
        assert g1 ** y == Y_1
        assert g2 ** y == Y_2


def test_issuance_basic():
    attributes = ["age", "name", "gender"]
    disclosed_attributes = {0: int.from_bytes(attributes[0].encode(), 'big')}
    hidden_attributes = {1: int.from_bytes(attributes[1].encode(), 'big'),
                         2: int.from_bytes(attributes[2].encode(), 'big')}
    user = User(disclosed_attributes, hidden_attributes)
    sk, pk = generate_key(attributes)
    issuer = Issuer(sk, pk)
    issue_request = user.create_issue_request(issuer.pk, hidden_attributes)
    signed_request = issuer.sign_issue_request(issuer.sk, issuer.pk, issue_request, disclosed_attributes)
    credential = user.obtain_credential(issuer.pk, signed_request)
    assert credential is not None
