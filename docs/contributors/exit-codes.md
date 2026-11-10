# Exit Codes

When a run ends non-zero, and why. The configuration scopes that decide a problem's handling are in [configuration.md](configuration.md).

A particular thorny issue with this tool rests around how to figure out what a "hard failure" (non zero exit code) means.  This can mean different things to people, and can depend on what they're trying to do.

General guidelines:

* If a user provides bad input (arguments, file formats), it's a *fail-fast* failure with a non-zero exit code where no amount of configuring can overcome.  
* If a user asks *directly* for something that can't be fulfilled, it's a *fail-eventually* failure - the tool cannot fulfil that request, but it can fulfil other requests.  These end in a non-zero exit code.  The user can override this behavior with configuration.
* If a user asks for something that *indirectly* leads to an issue, it's a *reported failure* but does not end in a non-zero exit code.  The user can override this behavior with configuration.
  * While, at first glance, we expect an indirect required dependency to trigger a fail-eventually fault (not having a required dependency means the requested item is broken), the determination of what's required is difficult to suss out without having access to the actual runtime environment.  We leave that as a problem for the user to solve.
  * The only trick here is whether the user pays attention to the error reports or only the exit code, and we provide the user limited controls for expressing these errors into the exit code.

Some examples help clarify the situation:

1. A person requested copying artifact `my-funny-tuna@1.23` from one repository to another.  The lookup couldn't find it on the source repository.  That's a *fail-eventually* failure - the user asked explicitly for one thing to happen, but it didn't.  It doesn't terminate everything quickly because the user may have asked for other artifacts that do resolve, but the direct request couldn't be fulfilled.
2. A person requested copying artifact `my-funny-tuna@1.23` from one repository to another, but it has 10 layers deep a testing dependency (used for internal testing during development) on the artifact `stupid-sturgeon@33.21`.  The lookup couldn't find the stupid sturgeon version on the source repository.  That's a *reported* failure - the user asked for something that happened, but that resulted in a down-stream consequence that the server couldn't fulfil.
3. A person requested copying artifact `my-funny-tuna@1.23` from one repository to another, but it has a runtime dependency on the artifact `stupid-sturgeon@999.999`.  This stupid sturgeon dependency is known malware.  The general rule would put this under a *reported* failure - the user asked for something which was fine, but validation rules prevented an indirect request.  However, we consider this particular issue severe enough to make it instead a *fail-eventually* for the artifact.
4. A person requested inspecting all matching artifacts listed in a `package-lock.json` file, but the server it's trying to reach is down.  This is *fail-eventually*, because a *content* resource required to perform the action wasn't available, but the user might have also asked for an additional artifact or other lock file.
5. A batch process requested copying newly added versions from one repository to another, but the malware feed source is down.  This is a *fail-fast* problem.
   * The difference between this example and the previous revolves around the kind of resource that was unavailable.  A *content* resource being down - the source repository - is *fail-eventually*: the artifacts it holds are the request, and the request is what couldn't be met.  A *screening* resource being down - an advisory database, a malware feed - is *fail-fast*, and deliberately harsher than the rule above would give it.  The consequence isn't a missing artifact but a **wrong answer**: a run that copies everything and reports nothing looks identical to a clean run, and would be read as one.  We would rather refuse to answer than answer "nothing found" when the truth is "nothing was asked".  An unparsable VEX document is the exception among screening inputs: it arrives as a lock file and vouches for the artifacts it names, so `vex-unparsable` is an artifact code a quarantine rule may excuse, and it aborts by default.
6. A person requests copying or inspecting all matching artifacts listed in a `package-lock.json` file, but the lock file format is wrong.  This results in *fail-fast*, because user input was wrong.
7. A person asks to inspect the dependencies of the Maven `ca.flounder:rubber-shoe:12.3`, and the repository hosts its POM file with an invalid format.  This is a *fail-eventually*, because the directly requested artifact couldn't be loaded.  The same thing would happen here if a parent POM has the invalid format that prevents the primary POM from loading right (say, unable to resolve a property).
8. A person asks to inspect the dependencies of the Maven `ca.flounder:rubber-shoe:12.3`, and a runtime dependency has an invalid POM file.  This is a *reported* failure, because the indirectly requested artifact couldn't be loaded.

These decisions aren't straight-forward, and can adjust as we examine more use cases.
