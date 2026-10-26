# Setup

The binary on your computer is an installer. It creates the server, installs Pocketcloud, hands you the recovery
phrase and the first VPN device, and then deletes everything it used. From then on the server is managed in the
interface; nothing of it remains on this computer.

## What you need

- A Hetzner Cloud project with an API token (read & write) for the server, and the token of the project that holds
  the DNS zones if that is a different one. Both are used during setup only and never stored; revoke them
  afterwards if you like.
- Your domain as a zone in Hetzner DNS.
- WireGuard on this computer and on your phone.

## Run it

```sh
pocketcloud setup mycloud
```

Setup asks for the tokens, the server size and location, the domains, the ssh user, the interface login, the first
device name and the WireGuard port, the Let's Encrypt address, and whether to reuse the recovery phrase of an
earlier installation (for a rebuild). Then it shows the plan and creates everything.

The cloud firewall lets in 80, 443, the WireGuard port, 53 for the challenge nameserver, and ICMP; ssh only
while setup runs, for this computer's address. Setup writes the public DNS records: the domain and its
wildcard, CAA, and the delegation of `_acme-challenge` to the server, which answers the certificate challenge
itself and therefore holds no DNS token.

## What you get at the end

1. **The recovery phrase**, 24 words, shown once and confirmed by three of them. It is the master key that seals
   every secret and the backups. Store it in your password manager. It is the only thing to keep.
2. **The first device's tunnel config**, written to `pocketcloud-mycloud.conf` in the current directory and shown
   as a QR code. Import it into WireGuard and delete the file.
3. **A phone**, if you say yes: a second device by QR code, so losing one device never locks you out.

Then setup hands ssh to the interface (the installer's key stops working), closes the firewall, and deletes its
run directory. The interface is at `https://pocketcloud.<domain>` with the tunnel active.

## If setup fails half way

Its state is in `~/.cache/pocketcloud/install-mycloud/` until it succeeds. Fix the cause and run the same command
again; it continues where it stopped. The run after the first asks for the recovery phrase, because the master
key only lived in memory.

## Afterwards

Apps, backups, alerts, Falco, ssh keys, upgrades and devices are configured in the interface. Lost every device:
see troubleshooting.md, "Every device is gone".
