using DiskMountUtility.Application.FileWatcher;
using DiskMountUtility.Application.Services;
using DiskMountUtility.Core.Interfaces;
using DiskMountUtility.Infrastructure.Cryptography;
using DiskMountUtility.Infrastructure.Persistence;
using DiskMountUtility.Infrastructure.Storage;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();

builder.Services.AddDbContextFactory<AppDbContext>();

builder.Services.AddSingleton<ILocalDbUnlocker, LocalDbUnlocker>();
builder.Services.AddScoped<ICryptographyService, HybridEncryptionService>();
builder.Services.AddScoped<IDiskRepository, DiskRepository>();
builder.Services.AddScoped<IVirtualDiskService, VirtualDiskManager>();
builder.Services.AddScoped<DiskManagementService>();
builder.Services.AddScoped<VaultFileWatcherService>();
builder.Services.AddScoped<RealtimeVaultSyncService>();
builder.Services.AddSingleton<RealtimeFileExplorerService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

using (var scope = app.Services.CreateScope())
{
    try
    {
        var diskManager = scope.ServiceProvider.GetRequiredService<IVirtualDiskService>() as VirtualDiskManager;
        if (diskManager != null && VaultKeyManager.IsInitialized)
        {
            await diskManager.InitializeAsync();
        }
        else
        {
            Console.WriteLine("Vault not initialized yet — skipping disk initialization.");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Skipping DB initialization: {ex.Message}");
    }
}

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();
