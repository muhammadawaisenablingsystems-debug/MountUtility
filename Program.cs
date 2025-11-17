using DiskMountUtility.Application.FileWatcher;
using DiskMountUtility.Application.Services;
using DiskMountUtility.Core.Interfaces;
using DiskMountUtility.Infrastructure.Cryptography;
using DiskMountUtility.Infrastructure.Persistence;
using DiskMountUtility.Infrastructure.Storage;
using MountUtility.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddServerSideBlazor()
       .AddCircuitOptions(options => { options.DetailedErrors = true; });

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

app.MapGet("/api/files/download", async (Guid diskId, string path, DiskManagementService diskService, ILogger<Program> logger) =>
{
    if (diskId == Guid.Empty || string.IsNullOrEmpty(path))
        return Results.BadRequest("diskId and path are required.");

    try
    {
        var stream = await diskService.OpenFileStreamAsync(diskId, path);
        if (stream == null)
            return Results.NotFound();

        var fileName = Path.GetFileName(path) ?? "download.bin";
        var contentType = "application/octet-stream";

        return Results.Stream(
            stream,
            contentType,
            fileName,
            enableRangeProcessing: true
        );
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Download failed for diskId={DiskId} path={Path}", diskId, path);
        return Results.StatusCode(500);
    }
});

app.Run();
