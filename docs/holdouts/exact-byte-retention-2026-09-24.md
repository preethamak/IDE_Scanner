# Exact-byte retention note

`NoahBit.api-reactor@0.0.1` remains in the advisory snapshot as an independently
reported malicious exact hash:

`ca272b481f630635cd059f85321dbc7be372e75820536ccbfd29dfcf571ab45c`

The original Marketplace download no longer returns bytes matching that hash,
and the exact VSIX is not retained in this repository. It is therefore excluded
from the publishable accuracy holdout until the original bytes are acquired and
stored in the private artifact vault. The scanner may still match the advisory
when an operator supplies the exact artifact; this note does not claim that the
current Marketplace response was scanned or that GuardRails independently
discovered the case.
