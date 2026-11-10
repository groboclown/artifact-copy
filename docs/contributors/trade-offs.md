# Trade-offs in the code


## Maven work-arounds

The Maven repositories were one of the first open submission repositories (nod to CERN), and they created it while the industry was still trying to figure out the right way to do things.  It was also created without strong tooling support, so there's all kinds of issues with it.  Being a write-once, only delete on malware repository, those mistakes are there for the keeping.

Thus, the Maven repository handler has specific code to identify known mistakes and try to work around them.

* Some artifacts added `.asc` files (cryptographic signature) on top of `.sha1` files (checksum validation).  If the original archive already has an `.asc`, then this signing of the checksum doesn't add anything.  Likewise, a checksum over a signature doesn't add anything, as the signature includes its own corruption identification mechanism.  The process will skip additional checking that isn't needed.
* Some artifacts added strange group or file names, such as including a `/` in the name.  These could lead to attempts at attacks on the system, so the Maven tooling ignores those resources.
* Some old and well-used artifacts include wrong POM files, where they list artifact IDs but no group.  In the well known cases, the Maven handler maps those to the right name.


## Fun Program Name vs Boring Name

This project has a boring name - it says what it does.  It could have a name like "prancing pencil", or something short for a quick run from the CLI.

I opted for a simple, boring name to make the purpose clear.  It does what it says.  It has a few actions used for bookkeeping that don't 100% align with the mission, but these support users so they don't need to add glue code or extra scripts to handle important functionality.  But that doesn't stop them from doing it if they need to.

I went with a long name.  It's long because it doesn't need to be short.  You run the program because you want to move artifacts between servers, which you either do from a cron schedule or on a one-time migration.  This scripted or rare scenario means you don't mind too much if you have to type in a long command name.  If you do run it often manually, shell aliases help.
