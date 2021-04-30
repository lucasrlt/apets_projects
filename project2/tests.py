from credential import generate_key
from petrelic.multiplicative.pairing import G1, G2, GT


def test_gen_key():
    attributes = ["age", "name", "gender"]
    L = len(attributes)
    (sk, pk) = generate_key(attributes)
    g1 = pk[0]
    g2 = pk[L+1]
    assert g1 == G1.generator()
    assert g2 == G2.generator()
    x = sk[0]
    assert 0 <= x < G1.order()
    X_1 = sk[1]
    assert g1**x == X_1
    X_2 = pk[L+2]
    assert g2**x == X_2
    for i in range(L):
        y = sk[i+2]
        Y_1 = pk[i+1]
        Y_2 = pk[i+L+3]
        assert 0 <= y < G1.order()
        assert g1**y == Y_1
        assert g2**y == Y_2
