import random
import os

class Mutator:
  def __init__(self, corpus_path, test_case_path="cases", seed=1337):
    self.corpus_path = corpus_path

    self.corpus = {}
    self.seed = seed  
    #self.corpus = []
    self.pool = {}

    self.known_points = []

    random.seed(self.seed)
    self.test_case_path = test_case_path
    self._load_corpus()

  def _load_corpus(self):
    for filename in os.listdir(self.corpus_path):
      filepath = os.path.join(self.corpus_path, filename)
      if os.path.isfile(filepath):
        self.corpus[filename] = bytearray(open(filepath, "rb").read())
        
  def _create_pool(self):
    for corpus_file in list(self.corpus.keys()):
      test_file, content = self.mutate(corpus_file, test_file=corpus_file + "_test_case")

      self.pool[test_file] = content

  def mutate(self, filename, test_file="test_case"):
    data = list(self.corpus[filename])
    methods = [self.bit_flip]

    mutation_method = random.choice(methods)
    data = mutation_method(data) 
    #data[idx]  ^= random.choice([2**0, 2**1, 2**2, 2**3, 2**4, 2**5, 2**6, 2**7])
    data = bytearray(data)

    path = os.path.join(self.test_case_path, test_file)

    with open(path, "wb") as f:
      f.write(data)
      
    return (path, data)
  
  def bit_flip(self, data):
    n = random.choice([1, 2, 4, 8, 16, 32])

    for idx in random.choices(range(len(data)), k=n):
      data[idx]  ^= random.choice([2**0, 2**1, 2**2, 2**3, 2**4, 2**5, 2**6, 2**7])

    return data

  def byte_flip(self, data):
    n = random.choice([1, 2, 4, 8, 16, 32])

    for idx in random.choices(range(len(data)), k=n):
      data[idx]  ^=  random.getrandbits(8)

    return data
    

  def add(self, content, trace):
    if set(trace) - set(self.known_points):
      new_point = list(set(trace) - set(self.known_points))
      self.known_points += new_point

      filename = "sample_" + str(len(self.corpus))
      self.corpus["sample_" + str(len(self.corpus))] = content
      print(trace)
      print(self.corpus)
   
  def __iter__(self):
    #self._create_corpus()
    self._create_pool()
    return self

  def __next__(self):
    if len(self.pool) == 0:
      self._create_pool()

    filename = list(self.pool.keys())[0]
    content = self.pool.pop(filename)

    return filename, content #self.mutate(filename) #random.choice(list(self.corpus.keys()))
