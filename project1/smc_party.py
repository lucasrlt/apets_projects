"""
Implementation of an SMC client.

MODIFY THIS FILE.
"""
# You might want to import more classes if needed.

import collections
import json
from server import publish_message, retrieve_private_message, send_private_message
from typing import (
    Dict,
    Set,
    Tuple,
    Union
)

from communication import Communication
from expression import (
    Expression,
    Secret,
    AddOp, SubOp, MultOp, Scalar
)
from protocol import ProtocolSpec
from secret_sharing import (
    reconstruct_secret,
    share_secret,
    Share,
)


# Feel free to add as many imports as you want.


class SMCParty:
    """
    A client that executes an SMC protocol to collectively compute a value of an expression together
    with other clients.

    Attributes:
        client_id: Identifier of this client
        server_host: hostname of the server
        server_port: port of the server
        protocol_spec (ProtocolSpec): Protocol specification
        value_dict (dict): Dictionary assigning values to secrets belonging to this client.
    """

    def __init__(
            self,
            client_id: str,
            server_host: str,
            server_port: int,
            protocol_spec: ProtocolSpec,
            value_dict: Dict[Secret, int]
    ):
        self.comm = Communication(server_host, server_port, client_id)

        self.client_id = client_id
        self.protocol_spec = protocol_spec
        self.value_dict = value_dict
        self.secret_ids_dict = {}  # Associate secrets sharer with corresponding secrets IDs; ex: {"Alice":alice's secrets' IDs}
        self.secret_ids = []
        self.shares_dict = {}

    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """

        # broadcast and get secrets ids from clients
        self.comm.publish_message(f"client_secrets_id", ",".join([x.id.decode() for x in self.value_dict.keys()]))

        for sid in self.protocol_spec.participant_ids:
            self.secret_ids_dict[sid] = self.comm.retrieve_public_message(sid, "client_secrets_id").decode().split(",")
            for id in self.secret_ids_dict[sid]:
                self.secret_ids.append(id)

        # broadcast own secret's shares to clients
        for secret in self.value_dict.keys():
            shares = share_secret(self.value_dict[secret], len(self.protocol_spec.participant_ids))
            for idx, sid in enumerate(self.protocol_spec.participant_ids):
                self.comm.send_private_message(sid, secret.id.decode(), shares[idx].value)

        # retrieve own share for each secret
        for sid in self.protocol_spec.participant_ids:
            for secret_id in self.secret_ids_dict[sid]:
                self.shares_dict[secret_id] = Share(self.comm.retrieve_private_message(secret_id).decode())

        # compute and broadcast self's result share
        expression = self.protocol_spec.expr
        my_share = self.process_expression(expression)
        self.comm.publish_message("computed share", str(my_share.value))
        shares = []
        for sid in self.protocol_spec.participant_ids:
            shares.append(Share(self.comm.retrieve_public_message(sid, "computed share").decode()))
        return reconstruct_secret(shares)


    # Retrieve own's share of a given secret
    def get_share(self, x: Secret):
        return self.shares_dict[x.id.decode()]

    # Get numerical index of self
    def get_self_id(self) -> int:
        return self.protocol_spec.participant_ids.index(self.client_id)

    # Perform a + or - operation on shares 
    def perform_operation(self, expr: Expression, a: Share, b: Share) -> Share:
        if isinstance(expr, AddOp): 
            return a + b
        elif isinstance(expr, SubOp):
            return a - b
        elif isinstance(expr, MultOp):
            return a * b

    # Perform a multiplication between two secrets
    def perform_secret_multiplication(self, expr: Expression, a: Share, b: Share):
        # Compute beaver triplets
        a_i, b_i, c_i = tuple(map(lambda x: Share(str(x)), self.comm.retrieve_beaver_triplet_shares(expr.id.decode())))
        x_share = a - a_i
        y_share = b - b_i

        self.comm.publish_message("castor_x", str(x_share.value));
        self.comm.publish_message("castor_y", str(y_share.value));

        # Reconstruct [x - a] and [y - b]
        x_shares = [] 
        y_shares = []
        for sid in self.protocol_spec.participant_ids:
            x_shares.append(Share(self.comm.retrieve_public_message(sid, "castor_x").decode()))
            y_shares.append(Share(self.comm.retrieve_public_message(sid, "castor_y").decode()))

        x = Share(str(reconstruct_secret(x_shares)))
        y = Share(str(reconstruct_secret(y_shares)))

        # Compute share result
        res = c_i + a * y + b * x
        if self.get_self_id() == 0:
            res -= x * y

        return res

    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    # ADD_SCALAR is a flag used to remember if we are adding a scalar
    def process_expression(
            self,
            expr: Expression,
            ADD_SCALAR=False) -> Share:

        if isinstance(expr, Secret):
            return self.get_share(expr)

        # Only one party uses the actual value of a scalar, others get 0 
        elif isinstance(expr, Scalar):
            return Share(str(0 if (ADD_SCALAR and self.get_self_id() != 0) else expr.value))

        # Perform an operation on a scalar
        elif isinstance(expr.a, Scalar) or isinstance(expr.b, Scalar):
            scalar = expr.a if isinstance(expr.a, Scalar) else expr.b
            secret = expr.b if isinstance(expr.a, Scalar) else expr.a

            if isinstance(expr, MultOp): # directly perform scalar multiplication
                return self.perform_operation(expr, Share(scalar.value), self.process_expression(secret))
            else: # perform scalar addition, if expr is a substraction just negate the scalar
                if self.get_self_id() == 0:
                    return self.perform_operation(AddOp(scalar, secret), Share(scalar.value if isinstance(expr, AddOp) else -scalar.value), self.process_expression(secret, ADD_SCALAR=True))
                else:
                    return self.process_expression(secret)

        # Perform an operation between 2 secrets
        elif (isinstance(expr.a, Secret) and isinstance(expr.b, Secret)) or isinstance(expr, MultOp):
            if isinstance(expr, MultOp):
                expr_a = self.process_expression(expr.a)
                expr_b = self.process_expression(expr.b)
                return self.perform_secret_multiplication(expr, expr_a, expr_b)
            else:
                return self.perform_operation(expr, self.get_share(expr.a), self.get_share(expr.b))

        # Directly perform the operation on the share results
        else:
            return self.perform_operation(expr, self.process_expression(expr.a), self.process_expression(expr.b))