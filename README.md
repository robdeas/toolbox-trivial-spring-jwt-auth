# toolbox-trivial-spring-jwt-auth
#Toolbox :

This toolbox provides useful Java utilities.

My "Toolbox" projects will be a series of projects designed to do common things in a number of different ways, from the complex to the trivial.
They could be used as skeletons to start working on your own code, or by comparing different versions to understand what needs to be done to do things in a better way.
They might also be useful as test stubs. 



---

This project's documentation (including this README.md) is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License  CC BY-SA 4.0 (Creative Commons Attribution-ShareAlike 4.0).

---

Code License:

This project's code is dual-licensed under the MIT License and the Apache License 2.0.
(Followed by the full license texts)

You may choose to use this software under the terms of either the MIT License or the Apache License 2.0.

##  A trivial spring jwt auth microservice. 

This is a microservice providing a ridicusly simple authentication microservice that might be useful for testsing purposes.

It has no roles at all.

Any changes to the list of users or the port are expected to be made before buildiing and using. 

The spring application.properties is the only config file.

It contains:

server.port by default 8081
app.username.regex=^(user1|user2|user3)$
app.passwordPrefix=
app.passwordSuffix=pass

This means the password for user1 will be user1-pass

You should change these fake values, as while this authentication service sends clear passwords and is not safe using standard known values could be even more dangerous if for example this service were to be more exposed than intended.

This service is trivial, but could still be useful in its own right in testing. 

I have removed logging, as it will probably just be simpler understand if you add you own when needed.

