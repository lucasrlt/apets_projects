"""
Classes that you need to complete.
"""

from typing import Any, Dict, List, Union, Tuple

# Optional import
from credential import generate_key
from issuer import Issuer
from serialization import jsonpickle

# Type aliases
State = Any


class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        self.issuer = None

    @staticmethod
    def generate_ca(
            subscriptions: List[str]
    ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        # generate secret and public key based on attributes (subscriptions) ;
        # we consider the public key to be the public param (maybe we will find others later?)
        sk, pk = generate_key(
            subscriptions)  # TODO: define clear types --> for now Attributes are bytes and not string hence the type pb here
        return jsonpickle.encode(sk), jsonpickle.encode(pk)

    def process_registration(
            self,
            server_sk: bytes,
            server_pk: bytes,
            issuance_request: bytes,
            username: str,
            subscriptions: List[str]
    ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        sk = jsonpickle.decode(server_sk)
        pk = jsonpickle.decode(server_pk)
        request = jsonpickle.decode(issuance_request)
        self.issuer = Issuer(sk, pk)
        issuer_attributes = {0: subscriptions[0], 2: subscriptions[
            2]}  # TODO: this is now completely arbitrary --> how to define disclosed attributes?
        blindSignature = self.issuer.sign_issue_request(self.issuer.sk, self.issuer.pk, request, issuer_attributes)
        # TODO: what is username used for?
        return jsonpickle.encode(blindSignature)

    def check_request_signature(
            self,
            server_pk: bytes,
            message: bytes,
            revealed_attributes: List[str],
            signature: bytes
    ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)
        s = jsonpickle.decode(signature)
        #TODO: revealed_attributes useful for ...?
        return self.issuer.verify_disclosure_proof(pk, s, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError()

    def prepare_registration(
            self,
            server_pk: bytes,
            username: str,
            subscriptions: List[str]
    ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError

    def process_registration_response(
            self,
            server_pk: bytes,
            server_response: bytes,
            private_state: State
    ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError

    def sign_request(
            self,
            server_pk: bytes,
            credentials: bytes,
            message: bytes,
            types: List[str]
    ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError
