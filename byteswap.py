class ByteSwapper:
   def __init__(self):
      pass

   def swap(self, orig):
      swapped = ''.join(sum([(c,d,a,b) for a,b,c,d in zip(*[iter(orig)]*4)], ()))
      return swapped

