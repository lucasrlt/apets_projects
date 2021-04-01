"""
Integration tests that verify different aspects of the protocol.
You can *add* new tests here, but it is best to  add them to a new test file.
ALL EXISTING TESTS IN THIS SUITE SHOULD PASS WITHOUT ANY MODIFICATION TO THEM.
"""

import statistics
import time
from statistics import mean
from multiprocessing import Process, Queue
import pandas as pd
import pytest

from expression import Expression, Scalar, Secret
from protocol import ProtocolSpec
from server import run
import matplotlib.pyplot as plt
import sys 

# from matplotlib import plot

from smc_party import SMCParty

sys.setrecursionlimit(5000)

def make_plot(title, csv_file):
    df = pd.read_csv(csv_file)
    df.plot(x=0, subplots=True, xlabel=title, logy=True)
    plt.savefig("perf_eval/" + title + ".png")
    # plt.show()
    plt.close()

class PerformanceEvaluator:
  def __init__(self, title=""):
    self.df = pd.DataFrame(columns=["Computation Time (in seconds)", "Bytes In", "Bytes Out"])
    self.computation_times = []
    self.bytes_in = []
    self.bytes_out = []
    self.title = title

  def performance_eval_callback(self, client_id, computation_time, bytes_in, bytes_out):
    self.computation_times.append(computation_time)
    self.bytes_in.append(bytes_in)
    self.bytes_out.append(bytes_out)

  def complete_results(self, id):
    self.df = self.df.append(pd.Series({
      "Computation Time (in seconds)": mean(list(self.computation_times)), 
      "Bytes In": mean(list(self.bytes_in)), 
      "Bytes Out": mean(list(self.bytes_out))
    }, name=str(id)))

    self.df.to_csv(f"perf_eval/{self.title}.csv")
    
    self.computation_times = []
    self.bytes_in = []
    self.bytes_out = []

  def plot_results(self):
    make_plot(self.title, f"perf_eval/{self.title}.csv")


def smc_client(client_id, prot, value_dict, queue):
    cli = SMCParty(
        client_id,
        "localhost",
        5000,
        protocol_spec=prot,
        value_dict=value_dict,
        performance_evaluation=True
    )
    res = cli.run()
    queue.put(res)
    print(f"{client_id} has finished!")


def smc_server(args):
    run("localhost", 5000, args)


def run_processes(server_args, performance_evaluator, *client_args):
    queue = Queue()


    server = Process(target=smc_server, args=(server_args,))
    clients = [Process(target=smc_client, args=(*args, queue)) for args in client_args]

    server.start()
    time.sleep(3)
    for client in clients:
        client.start()

    results = list()
    for client in clients:
        client.join()
        
    for client in clients:
        res = queue.get()
        performance_evaluator.performance_eval_callback("", res[1], res[2], res[3])
        results.append(res[0])

    server.terminate()
    server.join()

    # To "ensure" the workers are dead.
    time.sleep(2)

    print("Server stopped.")

    return results


def suite(parties, expr, expected, performance_evaluator):
    participants = list(parties.keys())

    prot = ProtocolSpec(expr=expr, participant_ids=participants)
    clients = [(name, prot, value_dict) for name, value_dict in parties.items()]

    results = run_processes(participants, performance_evaluator, *clients)

    print(results)


def test_number_additions(perf):
    """
    f(a) = a + a + ... + a
    """
    
    num_ops = [10, 100, 500, 1000, 2000, 4000]

    for num_op in num_ops:
      print("----- Performance evaluation for number of additions " + str(num_op))
      secret = Secret()
      parties = {}
      expr = secret
      parties["Alice"] = { secret: 5 }

      for i in range(num_op):
        expr = expr + secret

      suite(parties, expr, 0, perf)
      perf.complete_results(num_op)

    perf.plot_results()

def test_number_additions_scalar(perf):
    """
    f(a) = a + K0 + ... + K0
    """
    
    num_ops = [10, 100, 500, 1000, 2000, 4000]

    for num_op in num_ops:
      print("----- Performance evaluation for number of additions " + str(num_op))
      secret = Secret()
      parties = {}
      expr = secret
      parties["Alice"] = { secret: 5 }

      for i in range(num_op):
        expr = expr + Scalar(5)

      suite(parties, expr, 0, perf)
      perf.complete_results(num_op)

    perf.plot_results()

def test_number_multiplications(perf):
    """
    f(a) = a * a * ... * a
    """
    
    num_ops = [10, 100, 500, 1000, 2000, 4000]

    for num_op in num_ops:
      print("----- Performance evaluation for number of additions " + str(num_op))
      secret = Secret()
      parties = {}
      expr = secret
      parties["Alice"] = { secret: 2 }

      for i in range(num_op):
        expr = expr * secret

      suite(parties, expr, 0, perf)
      perf.complete_results(num_op)

    perf.plot_results()

def test_number_scalar_multiplications(perf):
    """
    f(a) = a * K * ... * K
    """
    
    num_ops = [10, 100, 500, 1000, 2000, 4000]

    for num_op in num_ops:
      print("----- Performance evaluation for number of additions " + str(num_op))
      secret = Secret()
      parties = {}
      expr = secret
      parties["Alice"] = { secret: 2 }

      for i in range(num_op):
        expr = expr * Scalar(2)

      suite(parties, expr, 0, perf)
      perf.complete_results(num_op)

    perf.plot_results()


def test_number_parties(perf):
  """
  f(x1, x2, ..., xn) = x1 + x2 + ... + xn
  """

  num_ops = 1000
  secrets = [Secret() for _ in range(num_ops)]

  num_parties = [1, 10, 25, 50, 100, 200, 300]

  expr = secrets[0]
  for i in range(1, num_ops):
    expr = expr + secrets[i]

  for num_party in num_parties:
    print("----- Performance evaluation for number of parties " + str(num_party))

    parties = {}
    secrets_per_parties = int(num_ops / num_party)

    secret_count = 0
    while secret_count < num_ops:
      idx = str(int(secret_count / secrets_per_parties))
      if idx not in parties.keys():
        parties[idx] = {}
      parties[idx][secrets[secret_count]] = 5
      secret_count += 1
      # print(secret_count, secrets_per_parties, int(secret_count / secrets_per_parties))

    # print(parties)
    suite(parties, expr, 0, perf)
    perf.complete_results(num_party)

  perf.plot_results()

    



test_number_additions(PerformanceEvaluator("Number of additions"))
test_number_additions_scalar(PerformanceEvaluator("Number of scalar additions"))
test_number_multiplications(PerformanceEvaluator("Number of multiplications"))
test_number_scalar_multiplications(PerformanceEvaluator("Number of scalar multiplications"))
test_number_parties(PerformanceEvaluator("Number of parties"))
# make_plot("Number of", "perf_eval/Number of.csv")


