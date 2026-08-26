using System;
using System.Collections.Generic;

namespace IssuerAPI.Databases;

public partial class Dbrequest
{
    public int Id { get; set; }

    public string? RegisterId { get; set; }

    public string CredentialId { get; set; } = null!;

    public DateTime? CreateDate { get; set; }

    public string? PreAuthorizedCode { get; set; }

    public string? Subject { get; set; }

    public string? TitleTh { get; set; }

    public string? FirstNameTh { get; set; }

    public string? LastNameTh { get; set; }

    public string? BirthDate { get; set; }

    public string? Gender { get; set; }

    public string? Address { get; set; }

    public string? DateOfIssuance { get; set; }

    public string? DateOfExpiry { get; set; }

    public string? TitleEn { get; set; }

    public string? FirstNameEn { get; set; }

    public string? LastNameEn { get; set; }

    public string? TxCodeHash { get; set; }
}
