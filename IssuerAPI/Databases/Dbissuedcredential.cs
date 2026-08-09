using System;
using System.Collections.Generic;

namespace IssuerAPI.Databases;

public partial class Dbissuedcredential
{
    public int Id { get; set; }

    public string RegisterId { get; set; } = null!;

    public string CredentialConfigurationId { get; set; } = null!;

    public DateTime? IssuedAt { get; set; }
}
