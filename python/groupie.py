# Groupie is an LMTP daemon with DKIM validation.
# It takes group management instructions from emails.
#
# In the ARPA2 projects, groups are not just email lists,
# but they cause many kinds of group services.  To make
# this happen, group memberships are managed in LDAP,
# from which services pull changes as they appear, and
# configure their interfaces accordingly.
#
# The interface for adding groups, or group members, is
# an arpa2shell that can be reached over SSH, but it also
# has an interface accepting JSON over GSS-API over
# AMQP 1.0.  This exceptional layering allows us to open
# up shells to anyone, but subject them to ACL scrutiny.
# It is this JSON-based interface that is being used by
# groupie.
#
# From: Rick van Rein <rick@openfortress.nl>


# For now, all commands are fixed and there is one domain.
# Future extensions will improve the dynamicity, of course.

# +group+subscribe+GROUP+MEMBER@arpa2.org
#	may remove explicit "decline" for this group,
#	operates under the domain arpa2.org,
#	creates GROUP+MEMBER as a sender alias,
#	adds GROUP+MEMBER to the group named GROUP,
#	supports translation of the sender to his alias,
#	and translation of the outgoing alias to the
#	sender's address.

# +group+subscribe+GROUP@arpa2.org
#	generates a random MEMBER and proceeds as for
#	+group+subscribe+GROUP+MEMBER@arpa2.org

# +group+unsubscribe+GROUP+MEMBER@arpa2.org
#	undoes any operations performed for
#	+group+subscribe+GROUP+MEMBER@arpa2.org
#	and may remove explicit "decline" for this group

# +group+unsubscribe+GROUP@arpa2.org
#	looks up the sender's MEMBER and proceeds as for
#	+group+unsubscribe+GROUP+MEMBER@arpa2.org

# +group+decline+GROUP@arpa2.org
#	explicitly refuses to be a MEMBER of GROUP
#	until overruled by +subscribe or +unsubscribe;
#	this is a bit like a negative subscription,
#	a kind of "leave me alone!" statement

# +group+invite+GROUP@arpa2.org
#	takes email addresses from the email body,
#	removes their refusal status if any, and then
#	sends them an active invitation, possibly with
#	an activation code; the use of an activation
#	code may be helpful for those without DKIM.

# +group+refuse+GROUP@arpa2.org
#	takes email addresses from the email body,
#	removes them from the group if the were on it,
#	and actively blocks their resubscription.

# +group+welcome+GROUP@arpa2.org
#	takes email addresses from the email body,
#	removes their refuse status if any, and
#	explicitly welcomes them.  It does not send
#	emails, but is otherwise like invite, just
#	more quietly so.


