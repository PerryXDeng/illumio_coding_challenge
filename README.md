This is a solution for a coding challenge.
# Solution Testing
Due to limited time, the solution is only tested
using assert statements. The conditions are the
based on the boolean statements and sample data
suggested in the instruction.
# Algorithmic Choices
I utilized a Python dictionary instead of a multidimensional
numpy (compiled in C) array to sacrifice super fast access
time for decreased memory waste when the number of rules
is small. The implementation for file parsing and packet 
rule matching is designed in a very functional manner, so
that they can easily be called in parallel or concurrently
if desired.
# Possible Refinements
More thorough testing and actual concurrency/parallelism
would be nice. Rules for frequently used ports or protocols
can be cached in memory while others can be stored on disk,
further reducing resource strain. The whole algorithm can
be implemented in and compiled from C for further speedup.
# Anything Else
This is one of the more interesting coding challenges I have
had. Check out [my other projects](https://github.com/PerryXDeng),
[one](https://github.com/PerryXDeng/os_fingerprint)
of which also has to do with high performance packet processing
and cybersecurity. For Illumio, I am mostly interested in the
data team. You can see my projects on github which extensively
works with all kind of data management, processing, analysis,
and visualization, using technologies such as MySQL, Spark, R,
and mathematical models such as deep learning, time-series, and hypothesis testing.
