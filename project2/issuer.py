from credential import SecretKey, PublicKey, IssueRequest, AttributeMap, BlindSignature, generate_key
from petrelic.multiplicative.pairing import G1, G2, GT, Bn


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
        C = request #TODO: with ZKP, change to C = request[0]

        prod = sk.X1 * C
        for i in range(len(issuer_attributes)):
            prod *= pk.Y1[i] ** Bn.from_binary(issuer_attributes[i])

        s_prime = (pk.g1 ** u, prod ** u)
        return s_prime
