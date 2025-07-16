# spdm-lib
This is a fork of spdm-lib from [Caliptra MCU](https://github.com/chipsalliance/caliptra-mcu-sw/tree/main/runtime/userspace/api/spdm-lib)

Long term the goal is to mold this into a platform independent implementation of an SPDM Requester and Responder. Short term is to get it working in a way that can be used outside of Caliptra MCU, and refactor to relocate things that may hamper embedded operation.

# Merge Policy

There are several branches within this repository, 2 of which are relevant at all times:

_upstream_ - This is a copy of the unmodified sources from the caliptra-mcu-sw repository. When updates come into the tree, they will be copied here and committed.

_openprot_ - This branch contains all openprot created commits. This branch will be rebased on top of upstream regularly.

The use of _main_ is TBD.
