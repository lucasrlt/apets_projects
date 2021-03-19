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
    AddOp
)
from protocol import ProtocolSpec
from secret_sharing import(
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
        self.shares_dict = {}

        


    def run(self) -> int:
        """
        The method the client use to do the SMC.
        """
        print(self.value_dict)

        # for secret in self.value_dict.values():
        #     shares = share_secret(secret, len(self.protocol_spec.participant_ids))
        #     for idx, sid in enumerate(self.protocol_spec.participant_ids):
        #         self.comm.send_private_message(sid, f"{self.client_id}_share", str(shares[idx]))

        # for sid in self.protocol_spec.participant_ids:
        #     my_share = self.comm.retrieve_private_message(f"{sid}_share")
        #     self.shares_dict[sid] = int(my_share.decode())

        expression = self.protocol_spec.expr
        print("Computing: ", repr(expression))
        my_share = self.process_expression(expression)
        self.comm.publish_message("computed share", str(my_share.value))
        shares = []
        for sid in self.protocol_spec.participant_ids:
            shares.append(Share(int(self.comm.retrieve_public_message(sid, "computed share").decode())))
        return reconstruct_secret(shares)

    # def add_secret(self, a: Secret, b: Secret) -> Share:
    #     a_share, b_share = -1, -1
    #     num_participants = len(self.protocol_spec.participant_ids)
        
    #     if a in self.value_dict.keys():
    #         a_shares = share_secret(self.value_dict[a], num_participants)
    #         for idx, sid in enumerate(self.protocol_spec.participant_ids):
    #             self.comm.send_private_message(sid, f"a_share", str(a_shares[idx]))
            
    #     a_share = int(self.comm.retrieve_private_message(f"a_share").decode())
    #     print(f"{self.client_id} a:{a_share}")



    #     if b in self.value_dict.keys():
    #         b_shares = share_secret(self.value_dict[b], num_participants)
    #         for idx, sid in enumerate(self.protocol_spec.participant_ids):
    #             self.comm.send_private_message(sid, f"b_share", str(b_shares[idx]))

    #     b_share = int(self.comm.retrieve_private_message(f"b_share").decode())
    #     print(f"{self.client_id} b:{b_share}")

    #     return Share(a_share + b_share)

  

    # Suggestion: To process expressions, make use of the *visitor pattern* like so:
    def process_expression(
            self,
            expr: Expression
        ) -> Share:

        if isinstance(expr, AddOp):
            if isinstance(expr.a, Secret) and isinstance(expr.b, Secret):
                print("Hallo", repr(expr))
                res = self.add_secret(expr.a, expr.b)

                # a + b
                # Secret()
                self.shares_dict[expr.a.id] + self.shares_dict[expr.b.id] 
                print(f"{self.client_id} Res:  {res}" )
                return res
            else:
                print("Coucou ici")
                expr_a = self.process_expression(expr.a)
                expr_b = self.process_expression(expr.b)
                print(f"{self.client_id} coucou_a: {expr_a}")
                print(f"{self.client_id} coucou_b: {expr_b}")
                return self.add_secret(expr_a, expr_b)
        elif isinstance(expr, Secret):
            return expr

        # if expr is an addition operation
        # :
            # ...

        # if expr is a multiplication operation:
        #     ...

        # if expr is a secret:
        #     ...

        # if expr is a scalar:
        #     ...
        #
        # Call specialized methods for each expression type, and have these specialized
        # methods in turn call `process_expression` on their sub-expressions to process
        # further.
        pass

    # Feel free to add as many methods as you want.
