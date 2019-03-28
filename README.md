# HET project

## Wot is dis ?!?

I just stumbled upon this old project (timestamp on files say 2016/12) which was a really cool thing i worked on, let me explain :

It was a proof of concept to see if it was possible to check the integrity of a .dll file (so basically anti tampering) with a dynamic approach.

First, a payload is built, which consists of a simple checker program which will scan DLL to see if it matches the initial build of it.
At first, this payload won't do anything, as it will not contain any data about the DLL itself. This data is injected when the actual DLL is built.

Next, this payload is encrypted using a custom key, leaving a placeholder space for a hash (only used for payload length).

When building the main DLL, a header file is created, containing a placeholder string of exactly the same size as the encrypted payload (spot (A)).
Another placeholder string is already in the source code, and is the size of a hash (spot (B)).

The main DLL is then built using standard toolings.

The main DLL is hashed without the placeholders. This hash is injected into the DLL in the spot (B).
Another hash is created, this time containing the DLL AND the hash (but not the payload placeholder). This hash is injected into the free space in the payload, and the payload is encrypted, this time with its placeholder filled.

The payload being complete, it is injected into the dll into the placeholder in spot (A).

The encryption key that was used to encrypt the payload is stored in a Windows key store. (this is the weakest point of this PoC)

When something is trying to access the DLL :
- The DLL checks itself using the hash in spot (B). If this hash is not valid, the DLL won't do anything.
- If the previous check passes, the DLL decrypts its payload, create a child process CMD, and dynamically replaces its memory. That way, nothing can tell a user (or even windows) that the program running under that memory space is not CMD.
- The payload checks the DLL file with its hash is valid
- If it is not, the DLL is effectively blocked, and nothing can be used (the program is killed in that PoC)
- If the test passes, the child process is killed (deleting traces of a DLL check), and the DLL is allowed to process its method call.

## Licence

All rights reserved, copyright Guillaume Gravetot 2016 - 2019

If you would like to use a part or this entire project, please contact me.