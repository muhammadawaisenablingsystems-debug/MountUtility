using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using MountUtility.WPF.Cryptography;
using MountUtility.WPF.Entities;

namespace MountUtility.WPF.Persistence
{
    public class AppDbContext : DbContext
    {
        public DbSet<VirtualDisk> VirtualDisks { get; set; }
        public DbSet<DiskFile> DiskFiles { get; set; }
        public DbSet<EncryptionMetadata> EncryptionMetadata { get; set; }

        private static readonly string DatabasePath =
         Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DiskMountUtility", "vaultdata.db");

        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            // Only configure if not configured by DI (useful for design-time tools)
            if (!optionsBuilder.IsConfigured)
            {
                var password = VaultKeyManager.GetPassword();

                var connectionString = new SqliteConnectionStringBuilder
                {
                    DataSource = DatabasePath,
                    Mode = SqliteOpenMode.ReadWriteCreate
                }.ToString();

                var connection = new SqliteConnection(connectionString);
                connection.Open();

                // Use SQLCipher default password-based encryption
                using (var cmd = connection.CreateCommand())
                {
                    cmd.CommandText = $"PRAGMA key = '{password.Replace("'", "''")}';";
                    cmd.ExecuteNonQuery();

                    // (Optional) Force SQLCipher 4 default settings for new DBs
                    cmd.CommandText = "PRAGMA cipher_compatibility = 4;";
                    cmd.ExecuteNonQuery();
                }

                optionsBuilder.UseSqlite(connection);
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // ---------------------------
            // VirtualDisk
            // ---------------------------
            modelBuilder.Entity<VirtualDisk>(entity =>
            {
                entity.ToTable("VirtualDisks");
                entity.HasKey(e => e.Id);

                entity.Property(e => e.Id).IsRequired();
                entity.Property(e => e.Name).HasMaxLength(255);
                entity.Property(e => e.FilePath).HasMaxLength(500);
                entity.Property(e => e.Status).HasConversion<string>();
                entity.Property(e => e.EncryptionAlgorithm).HasConversion<string>();
            });

            modelBuilder.Entity<VirtualDisk>()
                .HasOne(v => v.Metadata)
                .WithOne(m => m.VirtualDisk)
                .HasForeignKey<EncryptionMetadata>(m => m.VirtualDiskId)
                .OnDelete(DeleteBehavior.Cascade);

            // ---------------------------
            // DiskFile
            // ---------------------------
            modelBuilder.Entity<DiskFile>(entity =>
            {
                entity.ToTable("DiskFiles");
                entity.HasKey(e => e.Id);

                entity.Property(e => e.Name).HasMaxLength(255);
                entity.Property(e => e.Path).HasMaxLength(500);
                entity.Property(e => e.SizeInBytes);
                entity.Property(e => e.IsDirectory);
                entity.Property(e => e.CreatedAt);
                entity.Property(e => e.ModifiedAt);

                // Existing Kyber fields
                entity.Property(e => e.EncryptedContent);
                entity.Property(e => e.KyberCiphertext);
                entity.Property(e => e.KyberPublicKey);
                entity.Property(e => e.KyberSecretKeyEncrypted);
                entity.Property(e => e.KyberSecretKeyNonce);

                // New ECDH ephemeral public key per file
                entity.Property(e => e.EcdhEphemeralPublic);

                entity.Property(e => e.FileNonce);
                entity.Property(e => e.Salt);

                entity.HasOne(v => v.Disk)
                      .WithMany(d => d.Files)
                      .HasForeignKey(e => e.DiskId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            // ---------------------------
            // EncryptionMetadata
            // ---------------------------
            modelBuilder.Entity<EncryptionMetadata>(entity =>
            {
                entity.ToTable("EncryptionMetadata");
                entity.HasKey(e => e.Id);

                // Existing Kyber fields
                entity.Property(e => e.KyberCiphertext);
                entity.Property(e => e.KyberPublicKey);
                entity.Property(e => e.KyberSecretKeyEncrypted);
                entity.Property(e => e.KyberSecretKeyNonce);

                // New ECDH fields
                entity.Property(e => e.EcdhPublicKey);
                entity.Property(e => e.EcdhPrivateKeyEncrypted);
                entity.Property(e => e.EcdhPrivateKeyNonce);

                // Common metadata
                entity.Property(e => e.Nonce);
                entity.Property(e => e.Salt);

                entity.HasOne(v => v.VirtualDisk)
                      .WithOne(m => m.Metadata)
                      .HasForeignKey<EncryptionMetadata>(m => m.VirtualDiskId)
                      .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}