# Abuse stance and operator responsibilities

True censorship resistance means illegal and harmful content can exist on
this network, as it does on Tor and Freenet. The project takes a deliberate
position on this.

## Network level: no takedowns

There is no moderation, no content scanning, and no way for anyone (including
the people who wrote the software, and the holder of a network's genesis key)
to remove, seize or edit a name they do not own. This is what the project
exists to provide. Do not add such a mechanism; it would be a different
project.

The registry only stores names, public keys, server addresses and expiry
times. It does not store or serve site content.

## Individual level: block what you like, locally

Every resolver can block names, on the user's own machine, with their own
lists:

```sh
dweb-resolver --blocklist my-list.txt --blocklist community-list.txt
```

A list is one name per line, with `#` comments. Third parties are free to
publish shared blocklists; nobody is forced to use them, and the network
itself never applies them.

## Operator level: you are responsible for your own position

- **Registry node operators** hold and serve a list of names and addresses.
- **Site operators** are responsible for what their own server serves.
- **People who host or distribute the software** face different legal risks
  in different countries.

Each of these is your own legal position to understand. Nothing in this
project provides you with legal cover. Get legal advice before running a
public node, hosting a site, launching a network, or distributing the
software.

## Spam and squatting

Handled only by proof-of-work cost and expiry. There is no gatekeeper,
dispute process or reserved-name list. Unrenewed names return to the pool
after `expiry_days`.

## Keys

- Whoever holds a name's owner key owns the name. There is no recovery.
- A lost key means the name cannot be changed and will expire.
- A stolen key means the thief owns the name. Transfer to a new key quickly
  if you still can.
- Keep owner keys offline. Site servers need only their site key.
