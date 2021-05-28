from typing import List

from credential import SecretKey, PublicKey, IssueRequest, AttributeMap, BlindSignature, generate_key, DisclosureProof, \
    Attribute, verify
from petrelic.multiplicative.pairing import G1, G2, GT, Bn
from zkp import KnowledgeProof


class Issuer:
    """Correspond to the issuer/verifier in our scheme. It signs and verifies requests from the user.
    """

    def __init__(self, sk, pk):
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

        # Random value used as an exponent
        u = G1.order().random()

        # Create a signature corresponding to the user's request on disclosed attributes
        prod = sk.X1 * request.commitment
        public_generators = []
        for i in issuer_attributes.keys():
            public_generators.append(pk.Y1[i])
            prod *= pk.Y1[i] ** Bn.from_binary(issuer_attributes[i])
        # Generate the list of public generators, one per secret, to verify the commitment
        public_generators.append(pk.g1) # one more generator for _t_

        if not KnowledgeProof.verify_commitment(request, public_generators):
            return None

        s_prime = (pk.g1 ** u, prod ** u)
        return s_prime

    ## SHOWING PROTOCOL ##
    def verify_disclosure_proof(self, pk: PublicKey, disclosure_proof: DisclosureProof, message: bytes, disclosed_attributes: List[Attribute]) -> bool:
        """ Verify the disclosure proof

        Hint: The verifier may also want to retrieve the disclosed attributes
        """

        # generate the list of public generators
        # public_generators = []
        # for i in range(len(disclosure_proof.knowledge_proof.list_ss) - 1):
        #     public_generators.append(disclosure_proof.signature[0].pair(pk.Y2[i]))
        #
        # public_generators += [disclosure_proof.signature[0].pair(pk.g2)] # add the last generator
        com_prime = disclosure_proof.signature[1].pair(pk.g2)
        for i,a in enumerate(disclosed_attributes):
            com_prime /= disclosure_proof.signature[0].pair(pk.Y2[i+1])**Bn.from_binary(a)
        com_prime /= disclosure_proof.signature[0].pair(pk.X2)
        sign_valid = com_prime.eq(disclosure_proof.commitment)
        #is_kp_valid = KnowledgeProof.verify_commitment(disclosure_proof.knowledge_proof, public_generators, message)

        return not disclosure_proof.signature[0].eq(G1.neutral_element()) and sign_valid # or is_kp_valid
