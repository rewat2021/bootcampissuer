using System;
using System.Collections.Generic;

namespace IssuerAPI.Databases;

public partial class Dbissuerlog
{
    public int Id { get; set; }

    public string TeamId { get; set; } = null!;

    public string? CredentialType { get; set; }

    public string? HolderDid { get; set; }

    public string? IssuerDid { get; set; }

    public string? OfferId { get; set; }

    public string Status { get; set; } = null!;

    public string? ErrorCode { get; set; }

    public string? ErrorMessage { get; set; }

    public string? CredentialPayload { get; set; }

    public DateTime? CreatedAt { get; set; }
}
