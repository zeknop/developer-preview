# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Zeknod OÜ
"""The three relay calls this example makes, over `urllib` and nothing else.

The contract is `../../api/openapi-public.json` and the semantics a schema cannot
state are in `../../api/README.md`. Two of them decide how this module is
written, and both are easy to get wrong:

* **a refusal is not a verdict.** A `400`, `404`, `409` or `422` is the relay
  answering that it will not answer the question, the same way however often it is
  asked. No connection, a timeout, a `5xx`, a `429`, and a `200` whose body is not
  JSON or names no `valid`, are an outage: nobody checked anything. Neither is a
  statement about the message, so neither comes back from here as one — they are
  two different exceptions, and a caller that shows "this message was changed" for
  either has made a claim nothing supports;
* **a `401` and a `403` are read differently on the two paths**, because they mean
  different things there. On `POST /v1/sign` they are the relay's deterministic
  answer about the request: the key is not one it holds for that identity, or the
  key is good and it still will not sign — a suspended identity, a `From` the
  identity may not send as, a policy of the deployment. Retrying changes none of
  that, so they come back as refusals. `POST /v1/verify` asks for no credential at
  all; a `401` or a `403` there is something in front of the relay refusing US,
  which is nobody having checked the message — an outage, and never a reason to
  call a message `fail` (`delivered-envelope.md` §2 is explicit about it);
* **a repeated question is answered.** The relay marks the triple (identity,
  signature, message hash) for 24 hours, and a second question about the same
  triple is verified cryptographically again rather than served out of the mark;
  when the verdict is positive the answer is `valid: true` with
  `message: "Previously verified"`. So a reader who checks a message somebody else
  has already checked gets a verdict and not a refusal.

The base URL is the relay you were given. The example values in this package are
`https://relay.example.org` and `192.0.2.10`; nothing here has a default relay.
"""

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

#: `POST /v1/sign` wants the identity's own key in this field.
API_KEY_HEADER = "X-API-Key"

#: The status codes that are the relay refusing the question rather than failing
#: to answer it (`api/README.md`, "Which answers are an outage and which are not").
DETERMINISTIC_REFUSALS = (400, 404, 409, 422)

#: The same, for `POST /v1/sign`, where a `401` and a `403` are also deterministic
#: answers about the request and not an outage (`api/README.md`, "What each of the
#: codes means": the key is not one this relay holds, or it is and the relay will
#: still not sign).
SIGN_REFUSALS = DETERMINISTIC_REFUSALS + (401, 403)

DEFAULT_TIMEOUT = 15.0


class RelayUnavailable(Exception):
    """Nobody was asked anything: no connection, a timeout, a 5xx, a 429, or an
    answer that is not the shape an answer has. Never a verdict about a message —
    a caller decides what to do about not knowing, and the safe direction is the
    caller's own."""


class RelayRefused(Exception):
    """The relay answered that it will not answer this question, and will answer
    the same way next time. `status` is the code and `detail` the sentence it gave."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


@dataclass
class Capabilities:
    """`GET /v1/capabilities` — which versions of the signature input a relay has.

    `signs` and `verifies` are two fields because a caller must not have to assume
    they are one list: a build that could still verify a version it no longer signs
    would otherwise have no way to say so.
    """

    contract: str
    relay_id: str
    signs: list
    verifies: list
    signature_input_version: str
    #: Present and true only on a relay a deployment runs as a sandbox.
    sandbox: bool = False


def _request(
    url: str,
    method: str,
    body=None,
    headers=None,
    timeout=DEFAULT_TIMEOUT,
    refusals=DETERMINISTIC_REFUSALS,
):
    """One call. Returns the decoded JSON body, or raises one of the two above.

    `refusals` is the set of status codes this PATH answers deterministically;
    everything else is an outage. It is a parameter and not a constant because a
    `401` is a refusal of `POST /v1/sign` and an outage of `POST /v1/verify`.
    """
    data = None
    sent = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        sent["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=sent, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as answer:  # noqa: S310
            raw = answer.read()
    except urllib.error.HTTPError as error:
        raw = error.read()
        if error.code in refusals:
            raise RelayRefused(error.code, _detail(raw)) from None
        # A 5xx and a 429 are an outage; so is anything else unexpected. The text
        # of the answer is not repeated into the message: on some deployments it
        # carries the address and the certificate of a machine.
        raise RelayUnavailable(f"{url.rsplit('/v1/', 1)[-1]}: HTTP {error.code}") from None
    except urllib.error.URLError as error:
        raise RelayUnavailable(f"the relay could not be reached ({type(error).__name__})") from None
    except TimeoutError:
        raise RelayUnavailable("the relay did not answer in time") from None
    try:
        return json.loads(raw)
    except ValueError:
        raise RelayUnavailable("the relay answered something that is not JSON") from None


def _detail(raw: bytes) -> str:
    """The one sentence a refusal carries. A refusal of these paths is
    `{"detail": "<one sentence>"}`; the 422 of a malformed request carries the list
    of refused fields instead, which is printed as it came."""
    try:
        body = json.loads(raw)
    except ValueError:
        return "(the answer was not JSON)"
    if isinstance(body, dict) and "detail" in body:
        return body["detail"] if isinstance(body["detail"], str) else json.dumps(body["detail"])
    return json.dumps(body)


def capabilities(base_url: str, timeout: float = DEFAULT_TIMEOUT) -> Capabilities:
    """What this relay can sign and can verify.

    A signer asks this BEFORE it writes a version header, and the reason is a
    message that cannot be repaired: a relay older than this route accepts a
    signing request naming a newer version and signs the input it has always
    built, because the version field is optional and an unknown value in it was
    never refused. The signature comes back, the message leaves announcing a
    version its signature was not made over, and every verifier calls it invalid —
    permanently, about a message nobody touched. A 404 here is the relay saying it
    is that old, and the right answer to it is not to write a version at all.
    """
    answer = _request(f"{base_url}/v1/capabilities", "GET", timeout=timeout)
    return Capabilities(
        contract=answer.get("contract", ""),
        relay_id=answer.get("relay_id", ""),
        signs=list(answer.get("signs") or []),
        verifies=list(answer.get("verifies") or []),
        signature_input_version=answer.get("signature_input_version", ""),
        sandbox=bool(answer.get("sandbox")),
    )


def sign(
    base_url: str,
    api_key: str,
    uuid: str,
    content_hash: str,
    free_hash,
    timestamp: str,
    from_address: str,
    version,
    algorithm,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """`POST /v1/sign` — the relay signs the hashes of a message for an identity.

    The relay builds the signed bytes itself from the version and the algorithm the
    request names; it never signs bytes a caller handed it. The timestamp must be
    within 30 seconds of the relay's clock, and it is the SAME timestamp that is in
    the canonical object and in the header of the message: two different values
    would be two different messages.

    A `401` and a `403` from here are refusals, not an outage: the key, the
    identity or the `From` address is what has to change, and asking again with
    the same three changes nothing.
    """
    body = {
        "uuid": uuid,
        "content_hash": content_hash,
        "timestamp": timestamp,
        "from_address": from_address,
    }
    if free_hash is not None:
        body["free_hash"] = free_hash
    if version is not None:
        body["version"] = version
    if algorithm is not None:
        body["alg"] = algorithm
    return _request(
        f"{base_url}/v1/sign",
        "POST",
        body=body,
        headers={API_KEY_HEADER: api_key},
        timeout=timeout,
        refusals=SIGN_REFUSALS,
    )


def verify(
    base_url: str,
    uuid: str,
    signature: str,
    message_hash: str,
    timestamp: str,
    version=None,
    algorithm=None,
    free_hash=None,
    understands=None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """`POST /v1/verify` — does this signature hold for these hashes, and whose is it?

    No credential is asked for. Three things about the fields are worth stating,
    because each of them turns into a wrong verdict when it is got wrong:

    * `message_hash` is the hash RECOMPUTED from the bytes, never the one the
      header claims. The question is about the message in hand;
    * `version` is the version the MESSAGE announces, never the newest this caller
      could build: the version is inside the signed bytes, so naming another value
      makes the relay rebuild a different input and a message signed under an older
      version comes back invalid, about a message nobody touched;
    * `understands` is the newest version THIS caller can build, which is a
      different field entirely. Without it a relay cannot tell a caller written
      before v1.4 from this one asking about a message whose version field was
      taken off, and it answers 409 — a refusal — instead of a verdict.

    `source` and `proxy_secret` are reserved for the operator's own infrastructure
    and are not sent from here. No credential is sent either, which is why a `401`
    or a `403` from this path is an outage and not a refusal: it is something in
    front of the relay turning US away, so nobody looked at the message.
    """
    body = {
        "uuid": uuid,
        "signature": signature,
        "message_hash": message_hash,
        "timestamp": timestamp,
    }
    if version is not None:
        body["version"] = version
    if algorithm is not None:
        body["alg"] = algorithm
    if free_hash is not None:
        body["free_hash"] = free_hash
    if understands is not None:
        body["understands"] = understands
    answer = _request(f"{base_url}/v1/verify", "POST", body=body, timeout=timeout)
    if not isinstance(answer, dict) or "valid" not in answer:
        raise RelayUnavailable("the relay answered a body with no verdict in it")
    return answer
