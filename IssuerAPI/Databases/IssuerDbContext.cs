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

    public virtual DbSet<Dbissuerlog> Dbissuerlogs { get; set; }

    public virtual DbSet<Dbregister> Dbregisters { get; set; }

    public virtual DbSet<Dbrequest> Dbrequests { get; set; }

    public virtual DbSet<User> Users { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            var connStr = Environment.GetEnvironmentVariable("CONNECTION_STRING")
                ?? "server=localhost;port=3306;database=issuer;user=root;password=P@ssw0rd@1234;sslmode=None";
            optionsBuilder.UseMySql(connStr, ServerVersion.AutoDetect(connStr));
            //optionsBuilder.UseMySql("server=192.100.10.46;port=3306;database=issuer;user=root;password=P@ssw0rd@1234", Microsoft.EntityFrameworkCore.ServerVersion.Parse("8.0.45-mysql"));
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder
            .UseCollation("utf8mb4_0900_ai_ci")
            .HasCharSet("utf8mb4");

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
            entity.Property(e => e.CredentialId)
                .HasMaxLength(50)
                .IsFixedLength();
            entity.Property(e => e.RegisterId)
                .HasMaxLength(50)
                .IsFixedLength()
                .HasColumnName("RegisterID");
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.ToTable("users");

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
