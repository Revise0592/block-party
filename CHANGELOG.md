# Changelog

## 1.0.0

The first release of Block Party: one container that runs a family's game
servers at home, with a web panel for desktop and phone and a console server
list so Xbox, PlayStation and Switch players can join.

### Games

- **Minecraft Bedrock**: the panel downloads Mojang's official server, gives
  each server its own port, and keeps it updated (backing up first).
- **Minecraft Java (Paper)**, with the Java it needs, and plugins from Hangar
  and Modrinth (installed by the owner).
- **Consoles on Java servers** through Geyser and Floodgate, with ViaVersion,
  so Bedrock players and consoles can join Java worlds. A server with console
  players stays on the newest Minecraft version Geyser supports.
- **Hytale**, signed in with your Hytale account, with a console, the
  allowlist and operators, settings and backups.

### Running servers

- Start, stop, restart and update, a live console, automatic restart after a
  crash, and servers that were running come back after a reboot.
- Players: who's online, the allowlist, operators, and **Tried to join** with
  an **Allow** button.
- Settings as labelled controls with a line of explanation each, plus an
  advanced editor.
- Worlds and add-ons: install `.mcaddon` and `.mcpack` files, upload, switch
  and download worlds.
- Scheduled backups with one-click restore and download, taken without kicking
  anyone off.
- Overnight updates and restarts, only when nobody is playing.
- Import from Crafty Controller, which is only read, never changed.

### Joining

- A console server list and built-in DNS (replacing BedrockConnect): consoles
  see your servers under **LAN Games**, or in a menu after joining a featured
  server.
- **Friends outside the house**: open a server to friends, with UPnP or the
  port forwards to add by hand, and an invite that explains how to join.

### People and safety

- An owner account, plus accounts for the kids with what each one can do on
  each server. Only the owner can delete servers or manage accounts.
- Optional two-factor sign-in with an authenticator app and recovery codes.
- Notifications to a phone (ntfy), Discord, email or text message.
- Activity history for each server.

### The panel

- Two looks, **Control Room** and **Treehouse**, each light or dark, saved
  with your account. Pages use the whole window on wide screens and work on
  phones.
- A setup guide the first time, and a Help page.

### Installing

- An Unraid Community Apps template. The container needs its own IP on your
  home network (Network Type br0, fixed IP).
- `LIST_IP` is optional: the panel uses the container's own address.
- The container starts as root only to give a brand-new data folder to
  `nobody:users` (or `PUID`/`PGID`), then runs as that user.

### Upgrading from Blockheads Control Panel

The project was renamed. Use the image `ghcr.io/scottschneck/block-party` and
the container name `blockparty`; existing data folders work as they are.
