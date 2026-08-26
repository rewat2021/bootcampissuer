using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Pomelo.EntityFrameworkCore.MySql.Scaffolding.Internal;

namespace IssuerAPI.Databases;

public partial class IssuerDbContext : DbContext
{
    public IssuerDbContext()
    {
    }

    public IssuerDbContext(DbContextOptions<IssuerDbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Dbissuedcredential> Dbissuedcredentials { get; set; }

    public virtual DbSet<Dbissuerlog> Dbissuerlogs { get; set; }

    public virtual DbSet<Dbnonce> Dbnonces { get; set; }

    public virtual DbSet<Dbpresentationrequest> Dbpresentationrequests { get; set; }

    public virtual DbSet<Dbregister> Dbregisters { get; set; }

    public virtual DbSet<Dbrequest> Dbrequests { get; set; }

    public virtual DbSet<Dbuser> Dbusers { get; set; }

    // C-06: this used to be a hardcoded connection string with a real DB host/password committed
    // straight into source (EF scaffolding's default output — the "#warning" it generated telling
    // us to fix this was left in place and ignored). Every call site in the app uses `new
    // IssuerDbContext()` (parameterless) rather than DI-injected options, so OnConfiguring is the
    // only place this can be wired up. Reads CONNECTION_STRING from the environment — the same
    // variable name already used in Properties/launchSettings.json (dev) and docker-compose.yml's
    // .env (prod/lab) — so no code change is needed there, only removing the fallback credential.
    // Throws instead of silently falling back to a default so a missing/misconfigured environment
    // fails loudly at startup rather than quietly connecting to the wrong (or no) database.
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            string connectionString = Environment.GetEnvironmentVariable("CONNECTION_STRING");
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                throw new InvalidOperationException(
                    "CONNECTION_STRING environment variable is not set. Provide a MySQL connection string " +
                    "(e.g. \"server=...;port=3306;database=issuer;user=...;password=...;sslmode=None\") via " +
                    "the environment (see Properties/launchSettings.json for local dev, docker-compose.yml's " +
                    ".env for containers) — there is no hardcoded fallback.");
            }

            optionsBuilder.UseMySql(connectionString, Microsoft.EntityFrameworkCore.ServerVersion.Parse("8.0.45-mysql"));
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder
            .UseCollation("utf8mb4_0900_ai_ci")
            .HasCharSet("utf8mb4");

        modelBuilder.Entity<Dbissuedcredential>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbissuedcredential");

            entity.HasIndex(e => new { e.RegisterId, e.CredentialConfigurationId }, "uq_grant_config").IsUnique();

            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.CredentialConfigurationId)
                .HasMaxLength(200)
                .HasColumnName("credential_configuration_id");
            entity.Property(e => e.IssuedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("datetime")
                .HasColumnName("issued_at");
            entity.Property(e => e.RegisterId)
                .HasMaxLength(50)
                .HasColumnName("register_id")
                .UseCollation("utf8mb4_general_ci");
            entity.Property(e => e.Revoked).HasColumnName("revoked");
            entity.Property(e => e.RevokedAt)
                .HasColumnType("datetime")
                .HasColumnName("revoked_at");
        });

        modelBuilder.Entity<Dbissuerlog>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbissuerlog");

            entity.HasIndex(e => e.CreatedAt, "idx_created");

            entity.HasIndex(e => e.Status, "idx_status");

            entity.HasIndex(e => e.TeamId, "idx_team");

            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("datetime")
                .HasColumnName("created_at");
            entity.Property(e => e.CredentialPayload).HasColumnName("credential_payload");
            entity.Property(e => e.CredentialType)
                .HasMaxLength(100)
                .HasColumnName("credential_type");
            entity.Property(e => e.ErrorCode)
                .HasMaxLength(100)
                .HasColumnName("error_code");
            entity.Property(e => e.ErrorMessage)
                .HasColumnType("text")
                .HasColumnName("error_message");
            entity.Property(e => e.HolderDid)
                .HasMaxLength(255)
                .HasColumnName("holder_did");
            entity.Property(e => e.IssuerDid)
                .HasMaxLength(255)
                .HasColumnName("issuer_did");
            entity.Property(e => e.OfferId)
                .HasMaxLength(100)
                .HasColumnName("offer_id");
            entity.Property(e => e.Status)
                .HasColumnType("enum('success','failed')")
                .HasColumnName("status");
            entity.Property(e => e.TeamId)
                .HasMaxLength(50)
                .HasColumnName("team_id");
        });

        modelBuilder.Entity<Dbnonce>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbnonce");

            entity.HasIndex(e => e.Nonce, "uq_nonce").IsUnique();

            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("datetime")
                .HasColumnName("created_at");
            entity.Property(e => e.ExpiresAt)
                .HasColumnType("datetime")
                .HasColumnName("expires_at");
            entity.Property(e => e.Nonce)
                .HasMaxLength(100)
                .HasColumnName("nonce");
            entity.Property(e => e.Used).HasColumnName("used");
        });

        modelBuilder.Entity<Dbpresentationrequest>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity
                .ToTable("dbpresentationrequest")
                .UseCollation("utf8mb4_general_ci");

            entity.HasIndex(e => e.State, "uq_presentation_state").IsUnique();

            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.State)
                .HasMaxLength(100)
                .HasColumnName("state");
            entity.Property(e => e.Nonce)
                .HasMaxLength(100)
                .HasColumnName("nonce");
            entity.Property(e => e.RegisterId)
                .HasMaxLength(50)
                .HasColumnName("register_id");
            entity.Property(e => e.Status)
                .HasMaxLength(20)
                .HasColumnName("status");
            entity.Property(e => e.VerifiedPid)
                .HasMaxLength(50)
                .HasColumnName("verified_pid");
            entity.Property(e => e.FailureReason)
                .HasMaxLength(255)
                .HasColumnName("failure_reason");
            entity.Property(e => e.CreateDate)
                .HasColumnType("datetime")
                .HasColumnName("create_date");
            entity.Property(e => e.VerifiedAt)
                .HasColumnType("datetime")
                .HasColumnName("verified_at");
        });

        modelBuilder.Entity<Dbregister>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity
                .ToTable("dbregister")
                .UseCollation("utf8mb4_general_ci");

            entity.Property(e => e.Id).HasColumnName("ID");
            entity.Property(e => e.ContactName).HasMaxLength(100);
            entity.Property(e => e.RegisterDate)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("datetime");
            entity.Property(e => e.RegisterName).HasMaxLength(150);
        });

        modelBuilder.Entity<Dbrequest>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity
                .ToTable("dbrequest")
                .UseCollation("utf8mb4_general_ci");

            entity.Property(e => e.Id).HasColumnName("ID");
            entity.Property(e => e.Address)
                .HasMaxLength(500)
                .HasColumnName("address");
            entity.Property(e => e.BirthDate)
                .HasMaxLength(20)
                .HasColumnName("birth_date");
            entity.Property(e => e.CreateDate).HasMaxLength(6);
            entity.Property(e => e.CredentialId).HasMaxLength(1000);
            entity.Property(e => e.DateOfExpiry)
                .HasMaxLength(20)
                .HasColumnName("date_of_expiry");
            entity.Property(e => e.DateOfIssuance)
                .HasMaxLength(20)
                .HasColumnName("date_of_issuance");
            entity.Property(e => e.FirstNameEn)
                .HasMaxLength(100)
                .HasColumnName("first_name_en");
            entity.Property(e => e.FirstNameTh)
                .HasMaxLength(100)
                .HasColumnName("first_name_th");
            entity.Property(e => e.Gender)
                .HasMaxLength(10)
                .HasColumnName("gender");
            entity.Property(e => e.LastNameEn)
                .HasMaxLength(100)
                .HasColumnName("last_name_en");
            entity.Property(e => e.LastNameTh)
                .HasMaxLength(100)
                .HasColumnName("last_name_th");
            entity.Property(e => e.RegisterId)
                .HasMaxLength(50)
                .IsFixedLength()
                .HasColumnName("RegisterID");
            entity.Property(e => e.Subject)
                .HasMaxLength(255)
                .HasColumnName("subject");
            entity.Property(e => e.TitleEn)
                .HasMaxLength(50)
                .HasColumnName("title_en");
            entity.Property(e => e.TitleTh)
                .HasMaxLength(50)
                .HasColumnName("title_th");
            entity.Property(e => e.TxCodeHash)
                .HasMaxLength(64)
                .HasColumnName("tx_code_hash");
        });

        modelBuilder.Entity<Dbuser>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("dbusers");

            entity.HasIndex(e => e.Email, "email").IsUnique();

            entity.HasIndex(e => e.Username, "username").IsUnique();

            entity.Property(e => e.Id).HasColumnName("id");
            entity.Property(e => e.CreatedAt)
                .HasDefaultValueSql("CURRENT_TIMESTAMP")
                .HasColumnType("timestamp")
                .HasColumnName("created_at");
            entity.Property(e => e.Email)
                .HasMaxLength(100)
                .HasColumnName("email");
            entity.Property(e => e.FirstName)
                .HasMaxLength(100)
                .HasColumnName("first_name");
            entity.Property(e => e.LastName)
                .HasMaxLength(100)
                .HasColumnName("last_name");
            entity.Property(e => e.Password)
                .HasMaxLength(255)
                .HasColumnName("password");
            entity.Property(e => e.Username)
                .HasMaxLength(50)
                .HasColumnName("username");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
