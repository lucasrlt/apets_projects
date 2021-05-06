from credential import SecretKey, PublicKey, IssueRequest, AttributeMap, BlindSignature, generate_key, DisclosureProof
from petrelic.multiplicative.pairing import G1, G2, GT, Bn

from zkp import verify_petersen


class Issuer:

    def __init__(self, sk, pk):
        # TODO
        self.sk, self.pk = sk, pk

    ## ISSUANCE PROTOCOL ##
    def sign_issue_request(
            self,
            sk: SecretKey,
            pk: PublicKey,
            request: IssueRequest,
            issuer_attributes: AttributeMap
    ) -> BlindSignature:
        """ Create a signature corresponding to the user's request

        This corresponds to the "Issuer signing" step in the issuance protocol.
        """
        u = G1.order().random()
        C = request[0]
        zkp = request[1]

        if not verify_petersen(zkp[0], zkp[1], pk.Y1 + [pk.g1], C):
            return None

        prod = sk.X1 * C
        for i in range(len(issuer_attributes)):
            prod *= pk.Y1[i] ** Bn.from_binary(issuer_attributes[i])

        s_prime = (pk.g1 ** u, prod ** u)
        return s_prime

    ## SHOWING PROTOCOL ##

    def verify_disclosure_proof(
            self,
            pk: PublicKey,
            disclosure_proof: DisclosureProof,
            message: bytes
    ) -> bool:
        """ Verify the disclosure proof

        Hint: The verifier may also want to retrieve the disclosed attributes
        """
        generators = []
        for i in range(len(disclosure_proof[1][1])):
            generators.append(disclosure_proof[0][0].pair(pk.Y2[i]))
        return disclosure_proof[0][0] != G1.neutral_element() and verify_petersen(disclosure_proof[1][0],
                                                                                  disclosure_proof[1][1],
                                                                                  generators + disclosure_proof[0][
                                                                                      0].pair(pk.g2),
                                                                                  disclosure_proof[1][2], message)
