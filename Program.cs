using Core.Arango;
using Core.Arango.Protocol;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

var arango = new ArangoContext("Server=http://localhost:8529;Realm=_system;User=root;Password=;");

if (!await arango.Collection.ExistAsync("_system", "Claims") &&
    !await arango.Collection.ExistAsync("_system", "Summary") &&
    !await arango.Collection.ExistAsync("_system", "Users"))
{
    await arango.Collection.CreateAsync("_system", "Claims", ArangoCollectionType.Document);
    await arango.Collection.CreateAsync("_system", "Summary", ArangoCollectionType.Document);
    await arango.Collection.CreateAsync("_system", "Users", ArangoCollectionType.Document);
}

builder.Services.AddSingleton(arango);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Events.OnRedirectToLogin = (context) =>
        {
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        };
    });

const string myAllowSpecificOrigins = "_myAllowSpecificOrigins";

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(configurePolicy =>
    {
        configurePolicy.SetIsOriginAllowed(x => new Uri(x).IsLoopback)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseCors();

app.MapDefaultControllerRoute();

app.UseHttpsRedirection();

app.MapControllers();

app.Run();