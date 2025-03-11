This is a tivial implementation of JWT authentication. 

It wouldn't take most Java/Spring developers long to recreate it, and its ridicuously limited in capability.
Its so limited it doens't even have roles.

So why have I published it ?
 
The answer is when testing out cluster communications with external services, or just some different frameworks authentication and communications sometimes it is useful to have such a simple tool.
I think it also might be nice to use it in explaining concepts of JWT and how it can be integrated with other frameworks. 

It might be useful for me to have this available easily if I want to be able to include it in other projects and maybe it will be for someone else.

I will add some more complicated authentication systems at some point more similar to things I actually use.

It has a single build time config file

This allows the port on which it runs to be set

It also has a regex of allowed user names, and prexixes and suffexes for passwords to make them a bit changeable. Remember this tool is not secure at all and should not be used with real systems.

For example it sends the password in clear text, which would be a bad idea if it used https, but even worse it uses http.  

REMEMBER this is test/example code as a starting point. DO NOT use it in inaporpriate places.

It provides a starting point to quickly spin up the most basc auth service, not a proper auth service. 