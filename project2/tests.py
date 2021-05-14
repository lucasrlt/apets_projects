import jsonpickle
from credential import generate_key
from petrelic.multiplicative.pairing import G1, G2, GT

from issuer import Issuer
from user import User


# def test_gen_key():
#     attributes = ["age", "name", "gender"]
#     L = len(attributes)
#     (sk, pk) = generate_key(attributes)
#     g1 = pk[0]
#     g2 = pk[L + 1]
#     assert g1 == G1.generator()
#     assert g2 == G2.generator()
#     x = sk[0]
#     assert 0 <= x < G1.order()
#     X_1 = sk[1]
#     assert g1 ** x == X_1
#     X_2 = pk[L + 2]
#     assert g2 ** x == X_2
#     for i in range(L):
#         y = sk[i + 2]
#         Y_1 = pk[i + 1]
#         Y_2 = pk[i + L + 3]
#         assert 0 <= y < G1.order()
#         assert g1 ** y == Y_1
#         assert g2 ** y == Y_2


def test_issuance_basic():
    attributes = [b"age", b"name", b"gender"]
    disclosed_attributes = {2: attributes[0]}
    hidden_attributes = {0: attributes[1],
                         1: attributes[2]}

    all_attributes =  {0: hidden_attributes[0], 1: hidden_attributes[1], 2: disclosed_attributes[2]}
    user = User("coucou", all_attributes, hidden_attributes)
    sk, pk = generate_key(attributes)
    issuer = Issuer(sk, pk)
    issue_request = user.create_issue_request(issuer.pk, hidden_attributes)
    signed_request = issuer.sign_issue_request(issuer.sk, issuer.pk, issue_request, disclosed_attributes)
    credential = user.obtain_credential(issuer.pk, signed_request)
    
    assert credential is not None

def test_verify(): #TODO: verify get true for valid signature and false for s[0]=neutral or wrong signature
    pass

def test_ZKP(): #TODO: test pedersen_commitment and verify_pedersen methods all together
    pass

def test_showing_prot(): #TODO: test showing protocol flow (like issuance prot) I guess
    attributes = [b"age", b"name", b"gender"]
    hidden_attributes = {0: attributes[1],
                         1: attributes[2]}
    disclosed_attributes = {2: attributes[0]}
    all_attributes =  {0: hidden_attributes[0], 1: hidden_attributes[1], 2: disclosed_attributes[2]}

    user = User("coucou", all_attributes, hidden_attributes)
    sk, pk = generate_key(attributes)
    issuer = Issuer(sk, pk)

    issue_request = user.create_issue_request(issuer.pk, hidden_attributes)
    signed_request = issuer.sign_issue_request(issuer.sk, issuer.pk, issue_request, disclosed_attributes)
    credential = user.obtain_credential(issuer.pk, signed_request)

    assert credential is not None

    disclosure_proof = user.create_disclosure_proof(pk, credential, b"")

    verification = issuer.verify_disclosure_proof(pk, disclosure_proof, b"")
    assert verification is True

def test_encoding():
    all_attributes = {0: b'your_name', 1: b'restaurant', 2: b'bar', 3: b'dojo'}
    hidden_attributes = {0: all_attributes[0]}

    user = User(all_attributes[0], all_attributes, hidden_attributes)
    sk, pk = generate_key(all_attributes)
    issuer = Issuer(sk, pk)

    issue_request = user.create_issue_request(issuer.pk, hidden_attributes)
    # print(issue_request.)
    for s in issue_request.list_ss:
        print(s)
        jsonpickle.encode(str(s))

    signed_request = issuer.sign_issue_request(issuer.sk, issuer.pk, issue_request, disclosed_attributes)
    credential = user.obtain_credential(issuer.pk, signed_request)

    assert credential is not None

    disclosure_proof = user.create_disclosure_proof(pk, credential, b"")

    verification = issuer.verify_disclosure_proof(pk, disclosure_proof, b"")
    assert verification is True
    

test_issuance_basic()
test_showing_prot()
# test_encoding()