import random
import os

class Mutator:
  def __init__(self, corpus_path):
    self.corpus_path = corpus_path
  
    self.corpus = {}
    self.test_case_path = "cases"
    self._load_corpus()

  def _load_corpus(self):

    for filename in os.listdir(self.corpus_path):
      filepath = os.path.join(self.corpus_path, filename)
      if os.path.isfile(filepath):
        self.corpus[filename] = bytearray(open(filepath, "rb").read())

  def mutate(self, filename):
    data = self.corpus[filename]
    idx = random.choice(range(len(data)))

    data[idx]  ^= random.choice([2**0, 2**1, 2**2, 2**3, 2**4, 2**5, 2**6, 2**7])

    path = os.path.join(self.test_case_path, "test_case")
    with open(path, "wb") as f:
      f.write(data)

    return (path, data)

  def __iter__(self):
    return self

  def __next__(self):
    filename = random.choice(list(self.corpus.keys()))
    return self.mutate(filename) #random.choice(list(self.corpus.keys()))
