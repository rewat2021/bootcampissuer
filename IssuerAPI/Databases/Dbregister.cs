using System;
using System.Collections.Generic;

namespace IssuerAPI.Databases;

public partial class Dbregister
{
    public Guid Id { get; set; }

    public string RegisterName { get; set; } = null!;

    public string ContactName { get; set; } = null!;

    public DateTime RegisterDate { get; set; }

    public bool IsIssuer { get; set; }

    public bool IsHolder { get; set; }

    public bool IsVerifier { get; set; }

    public bool IsAdmin { get; set; }
}
