# Diameter Gy Interface Demo

A simple implementation of the Diameter Gy interface for online charging scenarios. This demo simulates quota management between a client (P-GW/PCEF) and server (OCS) using the freeDiameter framework.

## What it does

The demo simulates realistic mobile data charging scenarios:
- **Initial Request**: User starts browsing, requests data quota (800MB/1GB/1.2GB)
- **Update Request**: User consumes quota, reports usage and requests more
- **Terminate Request**: Session ends, reports final usage

## Files

- `client.c` - Gy client implementation (acts as P-GW/PCEF)
- `server.c` - Gy server implementation (acts as OCS)
- `client.conf` - freeDiameter configuration for client
- `server.conf` - freeDiameter configuration for server
- `Makefile` - Build configuration

## Building

```bash
make
```

## Running

Start the server first:
```bash
../freeDiameter/build/freeDiameterd/freeDiameterd -dddd -c server.conf
```

Then start the client:
```bash
../freeDiameter/build/freeDiameterd/freeDiameterd -dddd -c client.conf
```

The client will automatically run 10 complete charging sequences, each with Initial/Update/Terminate phases.

## Requirements

- freeDiameter library and headers
- Linux environment with root privileges (for Diameter stack)

## Output

You'll see detailed logs showing the charging flow between client and server, including quota requests, usage reports, and quota grants.