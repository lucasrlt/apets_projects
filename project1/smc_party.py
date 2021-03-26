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

        # for secret in self.value_dict.values():
        #     shares = share_secret(secret, len(self.protocol_spec.participant_ids))
        #     for idx, sid in enumerate(self.protocol_spec.participant_ids):
        #         self.comm.send_private_message(sid, f"{self.client_id}_share", str(shares[idx]))

        # for sid in self.protocol_spec.participant_ids:
        #     my_share = self.comm.retrieve_private_message(f"{sid}_share")
        #     self.shares_dict[sid] = int(my_share.decode())

        expression = self.protocol_spec.expr
        my_share = self.process_expression(expression)
        self.comm.publish_message("computed share", str(my_share.value))
        shares = []
        for sid in self.protocol_spec.participant_ids:
            shares.append(Share(self.comm.retrieve_public_message(sid, "computed share").decode()))
        return reconstruct_secret(shares)


    def add_secret(self, a: Share, b: Share) -> Share:
        return a + b

    def sub_secret(self, a: Share, b: Share) -> Share:
        return a - b

    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    def process_expression(
            self,
            expr: Expression,
            ADD_SCALAR=False) -> Share:

        if isinstance(expr, AddOp):
            if isinstance(expr.a, Secret) and isinstance(expr.b, Secret):
                return self.shares_dict[expr.a.id.decode()] + self.shares_dict[expr.b.id.decode()]
            # 2 cases for scala addition: scalar + expr_b or expr_a + scalar
            elif isinstance(expr.a, Scalar):
                # by convention, only first client in participants list adds scalar
                if (self.protocol_spec.participant_ids.index(self.client_id) == 0):
                    return Share(str(expr.a.value)) + self.process_expression(expr.b,ADD_SCALAR=True)
                else:
                    return self.process_expression(expr.b)
            elif isinstance(expr.b, Scalar):
                if (self.protocol_spec.participant_ids.index(self.client_id) == 0):
                    return self.process_expression(expr.a,ADD_SCALAR=True) + Share(str(expr.b.value))
                else:
                    return self.process_expression(expr.a)
            else:
                expr_a = self.process_expression(expr.a)
                expr_b = self.process_expression(expr.b)
                return expr_a + expr_b
        elif isinstance(expr, SubOp):
            if isinstance(expr.a, Secret) and isinstance(expr.b, Secret):
                return self.shares_dict[expr.a.id.decode()] - self.shares_dict[expr.b.id.decode()]
            else:
                expr_a = self.process_expression(expr.a)
                expr_b = self.process_expression(expr.b)
                return expr_a - expr_b
        elif isinstance(expr, Secret):
            return self.shares_dict[expr.id.decode()]
        elif isinstance(expr, Scalar):
            if (ADD_SCALAR and self.protocol_spec.participant_ids.index(self.client_id) != 0):
                return Share("0")
            else:
                return Share(str(expr.value))
        elif isinstance(expr, MultOp):
            # 2 cases for scala multiplication: scalar * expr_b or expr_a * scalar
            if isinstance(expr.a, Scalar):
                return Share(str(expr.a.value)) * self.process_expression(expr.b)
            elif isinstance(expr.b, Scalar):
                return self.process_expression(expr.a) * Share(str(expr.b.value))
            else:
                expr_a = self.process_expression(expr.a)
                expr_b = self.process_expression(expr.b)

                a_i, b_i, c_i = tuple(map(lambda x: Share(str(x)), self.comm.retrieve_beaver_triplet_shares(expr.id.decode())))
                x_share = expr_a - a_i
                y_share = expr_b - b_i

                self.comm.publish_message("castor_x", str(x_share.value));
                self.comm.publish_message("castor_y", str(y_share.value));

                x_shares = [] 
                y_shares = []
                for sid in self.protocol_spec.participant_ids:
                    x_shares.append(Share(self.comm.retrieve_public_message(sid, "castor_x").decode()))
                    y_shares.append(Share(self.comm.retrieve_public_message(sid, "castor_y").decode()))

                x = Share(str(reconstruct_secret(x_shares)))
                y = Share(str(reconstruct_secret(y_shares)))

                res = c_i + expr_a * y + expr_b * x
                if self.protocol_spec.participant_ids.index(self.client_id) == 0:
                    res -= x * y

                return res