from typing import List

from credential import PublicKey, AttributeMap, IssueRequest, BlindSignature, AnonymousCredential, Attribute
from petrelic.multiplicative.pairing import G1, G2, GT


class User:

    def __init__(self, disclosed_attributes: AttributeMap, hidden_attributes: AttributeMap):
        self.t = 0
        self.disclosed_attributes = disclosed_attributes
        self.hidden_attributes = hidden_attributes
        self.L = len(disclosed_attributes) + len(hidden_attributes)

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
        C = pk[0] ** self.t
        for user_index in user_attributes:
            C *= pk[user_index + 1] ** user_attributes[user_index]  # assuming attributes are Zp field elts
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
        s = response[0], response[1] / response[0] ** self.t

        # store s if valid (slide 44 ABC lecture)
        disclosed_prod = s[1].pair(pk[self.L + 1])
        for i in self.disclosed_attributes:
            disclosed_prod *= s[0].pair(pk[self.L + 3 + i]) ** (-self.disclosed_attributes[i])

        hidden_prod = s[0].pair(pk[self.L + 1]) ** self.t
        for i in self.hidden_attributes:
            hidden_prod *= s[0].pair(pk[self.L + 3 + i]) ** (self.hidden_attributes[i])

        if response[0] != G1.neutral_element() and disclosed_prod / s[0].pair(pk[self.L + 2]) == hidden_prod:
            return s
        else:
            return None
