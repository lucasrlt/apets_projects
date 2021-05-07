from typing import List

from credential import PublicKey, AttributeMap, IssueRequest, BlindSignature, AnonymousCredential, Attribute, verify, \
    DisclosureProof
from petrelic.multiplicative.pairing import G1, G2, GT, Bn, G1Element

from zkp import pedersen_commitment


class User:

    def __init__(self, username: str, attributes: List[Attribute], hidden_attributes: AttributeMap):
        self.t = 0
        self.username = username
        self.all_attributes = attributes
        self.hidden_attributes = hidden_attributes
        self.L = len(attributes)

        '''# Create a list of all attributes
        self.all_attributes = [None for _ in range(self.L)]
        for key in disclosed_attributes:
            self.all_attributes[key] = disclosed_attributes[key]
        for key in hidden_attributes:
            self.all_attributes[key] = hidden_attributes[key]'''

    ## ISSUANCE PROTOCOL ##

    def create_issue_request(
            self,
            pk: PublicKey,
            user_attributes: AttributeMap #TODO: changed hidden_attribute by user_attr since equal, verify funciton still consistent
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
        zkp = pedersen_commitment(
            [Bn.from_binary(item[1]) for item in user_attributes.items()] + [self.t], 
            [pk.Y1[idx] for idx in list(range(len(user_attributes.items())))] + [pk.g1], 
            C)
        return C, zkp

    def obtain_credential(
            self,
            pk: PublicKey,
            response: BlindSignature
    ) -> AnonymousCredential:
        """ Derive a credential from the issuer's response

        This corresponds to the "Unblinding signature" step.
        """
        # print(response)
        s = response[0], response[1] / (response[0] ** self.t)

        # reconstruct array of all attributes in order
        if verify(pk, s, self.all_attributes):
            return s
        else:
            return None

    ### SHOWING PROTOCOL ##
    def create_disclosure_proof(
            self,
            pk: PublicKey,
            credential: AnonymousCredential,
            message: bytes #TODO: really not useful?
    ) -> DisclosureProof:
        """ Create a disclosure proof """

        r = G1.order().random()
        t = G1.order().random()

        s = (credential[0] ** r, (credential[1] * (credential[0] ** t)) ** r)

        generators = []

        commitment = s[0].pair(pk.g2) ** t
        # print(self.hidden_attributes)
        for i, ai in enumerate(self.hidden_attributes.items()):
            print(Bn.from_binary(ai[1]))
            generator = s[0].pair(pk.Y2[i])
            commitment *= generator ** Bn.from_binary(ai[1])
            generators.append(s[0].pair(pk.Y2[i]))

        # compute ZKP
        
        zkp = pedersen_commitment(
            [Bn.from_binary(item[1]) for item in self.hidden_attributes.items()], 
            generators + [s[0].pair(pk.g2)], 
            commitment,
            b'', GT)

        print("Creation: ", commitment)

        return s, zkp, commitment
