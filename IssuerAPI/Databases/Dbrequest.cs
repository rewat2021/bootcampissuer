using System;
using System.Collections.Generic;

namespace IssuerAPI.Databases;

public partial class Dbrequest
{
    public int Id { get; set; }

    public string? RegisterId { get; set; }

    public string? CredentialId { get; set; }

    public DateTime? CreateDate { get; set; }

    public string? PreAuthorizedCode { get; set; }
}
