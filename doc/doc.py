'''
Documentation:

mpint:
  Represents multiple precision integers in two's complement format,
  stored as a string, 8 bits per byte, MSB first.  Negative numbers
  have the value 1 as the most significant bit of the first byte of
  the data partition.  If the most significant bit would be set for
  a positive number, the number MUST be preceded by a zero byte.
  Unnecessary leading bytes with the value 0 or 255 MUST NOT be
  included.  The value zero MUST be stored as a string with zero
  bytes of data.

  By convention, a number that is used in modular computations in
  Z_n SHOULD be represented in the range 0 <= x < n.
''