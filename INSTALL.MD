# Installing Groupie

> *How to get Groupie to work in your infrastructure.*


## Build and Runtime Dependencies

Groupie is built in Python.  It depends on

  * [lmtpd](https://pypi.python.org/pypi/lmtpd)
  * [python-ldap](https://pypi.python.org/pypi/python-ldap/2.4.41)
  * [dkimpy](https://pypi.python.org/pypi/dkimpy/0.6.2)


## Connections to MTAs

How to get information to arrive at the LMTP port?


### Postfix MTA

Services in the InternetWide Architecture start with `+` and their name.
What follows then can vary wildly, though it still is a matter of
configuration, so lookup tables with exact key matches are quite efficient
even when we have long lists of such mappings.

In a hosted domain's virtual domain definitions, we add mappings for the
various Groupie service addreses, including all possible group names,
to an underlying Groupie service identifier.  So, in `/etc/postfix/virtual`,
we might have

```
+group+subscribe+youcancook@eaxmple.com   +groupie@service.provider
+group+decline+youcancook@eaxmple.com     +groupie@service.provider
+group+unsubscribe+youcancook@eaxmple.com +groupie@service.provider
+group+invite+youcancook@eaxmple.com      +groupie@service.provider
+group+uninvite+youcancook@eaxmple.com    +groupie@service.provider
+group+refuse+youcancook@eaxmple.com      +groupie@service.provider
```

The only thing we need to do now, is to define the mapping to the
`groupie@service.provider` to be an LMTP mapping.  This is best done
in `/etc/postfix/transport`, using an entry like:

```
+groupie@service.provider  lmtp:inet:groupie.service.provider
```

This indicates that the emails to `+groupie@service.provider` will end
up being sent over LMTP to the host `groupie.service.provider` using the
standard port configured for LMTP.

Note how easy it is to use completely different service providers for
other services.  This is true for different group-management resources,
but also for completely different applications like editing ACLs on a
resource, or finding the best ASCII art rendering of a bunny.  The
general idea of this infrastructure is to pass on bits and pieces of the
infrastructure, in this case for email, to future plugin services.  It
may be compared to the ability of Nginx to present a web site but still
use a plethora of backend plugines for dynamic matters.



