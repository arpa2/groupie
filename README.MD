# Groupie &mdash; Using Email to Tack On to Groups

> *Groupie is een software service that enables groups to administer their
> members, on which ARPA2 applications can continue to build their
> collaborative structures.  Groupie administers things over email, using
> the fact that the majority of email is signed by DKIM.*

Groupie allows users to setup groups under their domain, and invite members
into their groups.  Members can address services for subscribing to a group.
Only when the group owner and the member agree will the membership be a fact.


## Context: InternetWide phase 2, IdentityHub

Groupie is part of the
[second phase](http://internetwide.org/blog/2016/06/24/iwo-phases.html),
[InternetWide Architecture](http://internetwide.org/tag/architecture.html)
and more specifically the
[identity structures](http://internetwide.org/blog/2016/12/18/id-6-inheritance.html)
involving such things as
[users and groups](http://internetwide.org/blog/2015/04/23/id-3-idforms.html)
and always with the intention to support you to
[Bring Your Own IDentity](http://internetwide.org/blog/2015/04/22/id-2-byoid.html)
anywhere you go online.

Specifically, the design of the InternetWide Architecture involves storage
of information in an LDAP repository, which is centrally available and which
can be easily distributed to other players, would the need arise.  This is
the
[Service Directory](http://internetwide.org/blog/2016/12/19/idhub-1-backend.html)
that is a vital part in the backend of this hosting infrastructure.


## Juggling Group Identities as in ARPA2 Projects

ARPA2 defines users as well as groups, but that is not everything; it allows
a great number of controls over light-weight aliases, and uses that heavily
in protection of the privacy of users.

Please understand that nothing about ARPA2 is closed or secretive;
in fact, we are hoping to inspire many Internet service projects to integrate
their use of identity with the system we are building to achieve better
personal control over our online identity and, most importantly, better
integration between tools.

Even in a group, the user does not have to surrender their userid or even
their (remote) email address.  Group members have a membership name which
is represented as a refinement of the group name, pretty much just like
the aliases.  The idea is that group members can address each other by
referring not to the group, but by adding member names to it.  This is
simpler than it seems; communication in the group will come `From:` a
particular group member, thereby revealing their group identity.  All
ARPA2 systems can work with this, and only the group-support software is
really involved in mapping between those group member names and real local
aliases and/or remote email addresses.

So, imagine `john@example.com` signing up for `youcancook@example.com`, so
locally.  John picks an alias, `youcancook+charcoalman@example.com` for
his membership to the list (or he might leave it to the limited fantasy
of Groupie, which usually means that he ends up with `043510-04363` or
something similarly appealing.

When communicating on the list, John always has a choice or replying to
a sender or to all on the list.  In addition, there is some syntaxis
that allows sending to the list plus selected dormant members, or minus
a member whose birthday surpirse needs to be discussed.  Often, there
will be a group member named `record` which stores everything that
passes for future reference.  Sometimes, an dormant group member `nsa`
(short for Non-Subscriber-Archive) may be added in to make an exchange
available publicly.  All this ends up in addresses with local parts
like `youcancook+mary` for just Mary, `youcancook` for the entire group
of non-dormant members, and `youcancook+-+record` for off-the-record
talk.

Mary, by the way, may be a remote member.  The member name `mary` in
`youcancook+mary` does not show that; a good example of how the member
names help to protect privacy of group members.  WHo's who is however
known to the group owner, who might need it to tackle abuse.


## Mechanics from LMTP to LDAP

Requests arrive with Groupie over an LMTP port.  This is a customary backend
to which MTAs can send email.  Such email will have a human sender, and it
will be delivered to an identity known to Groupie.  These identities look
something like `+group+subscribe+piecrusts@baking.fun` &mdash; in other
words, an email address under a domain, with a few words in the local part.

After splitting the words by their `+` separators, they look like commands.
Groupie will ignore the first word, which is the service name that it got
from the MTA administrator, but after that has served the purpose of routing
email to Groupie's LMTP port that is no longer of interest.  The rest is
a command and parameters, usually a name of a group under the domain that
follows after `@`.

These commands are used to operate on data structures stored in LDAP.
Specifically, LDAP holds nodes for groups, with more specific nodes
for group members.  These group members point to a local alias or a
complete remote address for a remote user.  Note that a remote address
is an email address, or similar `user@domain` style notation.  This is
the form that we always use in ARPA2 Projects.

The commands that Groupie supports are focussed on editing these structures
in LDAP, and given that understanding the work done by Groupie is really
very simple; it takes in email, derives a command from it, and applies it
to the Service Directory LDAP.  Its findings may be reported back to the
requester.


### It's Elementary, My Dear Watson

The reasons that Groupie's functions are elementary is that all use of the
group structures is done elsewhere.  This is vital, because there could be any
number of protocols implementing collaborative semantics with group sharing.
So, Groupie does not administer email groups, but rather leaves that to a
separate component.  This often takes the form of a
[SteamWorks Pulley](http://steamworks.arpa2.net/pulley.html)
application with a
[suitable script](https://github.com/arpa2/idhub-service/blob/master/doc/idhub-servicedir.ply)
to extract the group membership relations from LDAP and, through a simple
[Pulley Backend](https://github.com/arpa2/steamworks/blob/master/docs/pulleyback-api.md)
that delivers the relations analysed from LDAP to an application.  If you
want your groups to end up in a couple of DBM databases for use by Postfix,
then you can easily build that.

So, all that Groupie needs to care about is adding and removing group
members.  Given the
[structures for groups](https://github.com/arpa2/idhub-service/blob/master/doc/arpa2-servicedir.schema)
with separate acceptance of a member by a group and of a group by a member,
it is even really straightforward to do this.

It is not a coincidence that the task of Groupie is so elementary.  It is a
result of our conscious choice to use LDAP, with its rich semantics, fine
data model and precondition-protected atomic updates of fairly complex objects.
It is also not a shrugging matter that Groupie is so elementary;
there can be other interfaces to the same backend, especially
[SteamWorks Crank](http://steamworks.arpa2.net/crank.html)
maps LDAP objects into a the HTTP space through JSON and a RESTful interface.
The authentication and authorisation mechanisms may differ, but access to
the underlying data model is... elementary.  And it is also relatively easy
to keep the two models in sync.

Why do we need Groupie when we can have the interactive marvels of a web
interface?  Obviously not because we like to be retro.  Groupie provides us
with a bootstrapping mechanism for secure administration of a website.  With
DKIM readily available to anyone, it is now possible to make reasonable
assumptions about the authenticity of users, even those that are external
to ARPA2 tooling.


## Secure Access to Groupie

If there's anything that Groupie will not tolerate, it is insecure access
attempts.  The old-school approach to security to list membership is to
send back an email with a code that has to be replicated by the receiver
either in a reply email or through a web link.  Groupie is willing and able
to be retro, by falling back to those procedures of last century.  But it has
not been idling around since those old days, and has evolved.

Today, many users have their email signed silently with DKIM.  In fact, the
most probably place where this is done is at the origin, so at their email
sending service provider.  This is great news, because whatever is protected
by DKIM cannot change while it passes through.  Combine that with the habit
of TLS-encrypted connections and the common ability to pass mail directly
from the sender domain to the recipient domain, and we have a pretty secure
setup.

DKIM signs email bodies as well as a selection of headers.  The selection
is dynamic, and determined by the signer, so the email message originator.
Usually, the `To:` and `Cc:` headers are signed, as is the `From:` address
and the `Subject:` line.  In short, we have some really interesting information
to act on (and we can always fall back on retro practices if we need to).

When a messages arrives over LMTP, the MTA should set a header to the
original email address, holding the `+group+subscribe+bla@talks.cheap` style
address for the Groupie service.  This address is (or these addresses are)
used to sum up one or more actions to perform.  Let's take Postfix as an
example, and say that the Groupie service is in the `X-Original-To:` header.

The addresses provided in `X-Original-To:` are not of any cryptographic
standing.  They really need to be validated in some way.  This can be
done by validating that it has occurred in a DKIM-signed header.  If not,
it may have been supplied in an unsigned header, in which case retro security
needs to kick in.

The other bit of information that we are interested in, is the sender of
the message.  DKIM can validate a sender domain, and we shall make the
(not too) liberal assumption that the domain feels better than to allow one
user to fake the identity of another.  In fact, it is up to the domain how
well it wants to be protected.  DKIM key material with or without protection
by DNSSEC, it is a choice that would reflect back on the security of the
group members.  Anyhow, the vital point is that the sender address can be
learned reliably from the `From:` header, which is also customarily
signed with a `DKIM-Signature:` &mdash; and if not, Groupie zaps back to
retro times.

Given an authenticated command and sender, Groupie can perform most of
its tasks.  For some tasks it requires the owner to be the sender.  For
others, anyone is welcome.  Yet others require group membership.  In some
of the cases, the `Subject:` is needed, of course under protection from
the `DKIM-Signature:` or else... back to old times and bad habits.
(The `Subject:` is sometimes used to contain a requested member name.)


## Supported Commands

Groupie supports the following commands, which we shall write in the
form after splitting over the `+` symbols:

  * `group help [<group>]` requests information [about `<group>`] by
    reply mail.
  * `group subscribe <group>` and `group unsubscribe <group>` add or
    remove a member from `<group>`.  The member name is randomly
    picked by Groupie or, given a secure `Subject:` header with a
    `<group>+<member>` name, it will try to use that member name.
    The command `group decline <group>` is an explicit but negative
    form of subscription.
  * `group invite <group>` and `group uninvite <group>` are used by
    the group owner to invite members.  There is an explicit negative
    form as well, `group refuse <group>`.  The body of the email is
    formed as lines holding one email address each, and then when a
    message should be sent to the victims, an empty line and the
    message to send.  Only plaintext bodies are processed, the rest
    is stripped away because processing it is errprone and may be
    harmful by leaking email addresses between members.
  * There is bound to be a facility for listing group members, as
    people always seem to feel comfort in breaching either privacy
    or security.  Given that the membership names are relatively
    private already, this may not be a high-value commodity, even
    though it would be for spammers who need contact end points.
  * A few more commands for adminsitrative purposes are bound to
    arise.  It may be beneficial to create groups over mail, for
    example.  Time will tell and ACLs will be in the way.

As mentioned before, the `group` part of this command is not valuable;
consider it your `argv[0]` name indication, a thing to use in result
printouts but never something on which to build value.




