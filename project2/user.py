from typing import List

from credential import PublicKey, AttributeMap, IssueRequest, BlindSignature, AnonymousCredential, Attribute, verify, DisclosureProof
from petrelic.multiplicative.pairing import G1, G2, GT, Bn


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
            C *= pk.Y1[user_index] ** Bn.from_binary(user_attributes[user_index])  # assuming attributes are Zp field elts
        # TODO: ZKP
        return C

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
        pk: PublicKey,
        credential: AnonymousCredential,
        message: bytes
    ) -> DisclosureProof:
        """ Create a disclosure proof """
    
        r = G1.order().random()
        t = G1.order().random()

        s = (credential[0] **r, (credential[1] * credential[0] **t) **r)

        generators = []

        commitment = s[0].pair(pk.g2)** t
        for i, ai in enumerate(self.hidden_attributes):
            generator = s[0].pair(pk.Y2[i])
            commitment *= generator **ai
            generators.append(s[0].pair(pk.Y2[i]))

        # compute ZKP
        zkp = petersen_commitment(self.hidden_attributes.items() + [self.t], generator + s[0].pair(pk.g2), commitment, b'', GT)
         
        return s, zkp, commitment

    



# store s if valid (slide 44 ABC lecture)
        # disclosed_prod = s[1].pair(pk[self.L + 1])
        # for i in self.disclosed_attributes:
        #     disclosed_prod *= s[0].pair(pk[self.L + 3 + i]) ** (-Bn.from_binary(self.disclosed_attributes[i]))

        # hidden_prod = s[0].pair(pk[self.L + 1]) ** self.t
        # for i in self.hidden_attributes:
        #     hidden_prod *= s[0].pair(pk[self.L + 3 + i]) ** (Bn.from_binary(self.hidden_attributes[i]))