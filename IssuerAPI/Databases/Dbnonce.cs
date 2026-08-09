using System;
using System.Collections.Generic;

namespace IssuerAPI.Databases;

public partial class Dbnonce
{
    public int Id { get; set; }

    public string Nonce { get; set; } = null!;

    public DateTime ExpiresAt { get; set; }

    public bool Used { get; set; }

    public DateTime? CreatedAt { get; set; }
}
