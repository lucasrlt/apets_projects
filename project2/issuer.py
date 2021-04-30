from credential import SecretKey, PublicKey, IssueRequest, AttributeMap, BlindSignature, generate_key
from petrelic.multiplicative.pairing import G1, G2, GT


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
        prod = G1.neutral_element()
        for i in range(len(issuer_attributes)):
            prod *= pk[i + 1] ** issuer_attributes[i]
        s_tilda = (pk[0] ** u, (sk[1] * C * prod) ** u)
        return s_tilda
