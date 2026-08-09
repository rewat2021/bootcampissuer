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

    public virtual DbSet<Dbregister> Dbregisters { get; set; }

    public virtual DbSet<Dbrequest> Dbrequests { get; set; }

    public virtual DbSet<Dbuser> Dbusers { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        // C-06: no hardcoded DB credential fallback. Must be supplied via CONNECTION_STRING env var.
        // Re-running `dotnet ef dbcontext scaffold` (e.g. to pick up a new column/table) WILL
        // overwrite this method with a literal connection string + password again — re-apply this
        // block afterward every time, or scaffold with `--no-onconfiguring` so it's left alone.
        var connStr = Environment.GetEnvironmentVariable("CONNECTION_STRING");
        if (string.IsNullOrWhiteSpace(connStr))
        {
            throw new InvalidOperationException(
                "CONNECTION_STRING environment variable is not set. Refusing to start with a hardcoded database credential.");
        }
        optionsBuilder.UseMySql(connStr, Microsoft.EntityFrameworkCore.ServerVersion.Parse("8.0.45-mysql"));
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
                .HasColumnName("register_id");
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
            entity.Property(e => e.CreateDate).HasMaxLength(6);
            entity.Property(e => e.CredentialId).HasMaxLength(1000);
            entity.Property(e => e.RegisterId)
                .HasMaxLength(50)
                .IsFixedLength()
                .HasColumnName("RegisterID");
            entity.Property(e => e.Subject)
                .HasMaxLength(255)
                .HasColumnName("subject");
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
