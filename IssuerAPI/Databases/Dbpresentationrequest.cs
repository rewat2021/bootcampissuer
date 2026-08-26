using System;
using System.Collections.Generic;

namespace IssuerAPI.Databases;

// OID4VP presentation request/response tracking — new table backing PresentationController. One row
// per "please present your PID VC" request the issuer sends out before it will issue a Standard VC
// (see Sequence Diagram - P2 v.1.4.md, steps 1-18). Deliberately separate from Dbrequest (which
// tracks OID4VCI credential offers) since this is a different protocol/purpose, even though the
// citizen session (RegisterId) links the two together.
public partial class Dbpresentationrequest
{
    public int Id { get; set; }

    // The OID4VP "state" — also this row's lookup key. Embedded in the authorization request and
    // echoed back by the wallet in the presentation response (direct_post) so we know which pending
    // request a given vp_token belongs to.
    public string State { get; set; } = null!;

    // Server-issued, single-use per request. Must be echoed inside the Key Binding JWT's "nonce"
    // claim (holder PoP) — this is what stops a captured/replayed vp_token from a past request being
    // reused against a new one.
    public string Nonce { get; set; } = null!;

    // The citizen (ClaimTypes.NameIdentifier — dbusers.Id or ThaID PID) who initiated this, i.e. who
    // is being asked to present their PID VC. Nullable defensively but should always be set — every
    // caller is [Authorize]d.
    public string? RegisterId { get; set; }

    // pending | verified | failed
    public string Status { get; set; } = "pending";

    // PID extracted from the presented PID VC once verification succeeds — lets the caller confirm
    // the presented credential actually belongs to the same citizen who requested the Standard VC,
    // not just "a" validly-signed, unrevoked PID VC from a trusted issuer.
    public string? VerifiedPid { get; set; }

    public string? FailureReason { get; set; }

    public DateTime? CreateDate { get; set; }

    public DateTime? VerifiedAt { get; set; }
}
