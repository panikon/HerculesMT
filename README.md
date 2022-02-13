Hercules Multi-threaded
========
This is a fork of [Hercules](https://github.com/HerculesWS/Hercules).

Currently most of the work in Login and Char servers is done, albeit not tested in production or with multiple users, sockets are only enabled in Windows.
See [core_design](doc/core_design.md) for more information on how the basic core design of the server is being changed in order to support multiple concurrent threads.
