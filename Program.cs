using System.Text.Json.Nodes;
using Core.Arango;
using Core.Arango.Linq;
using Core.Arango.Protocol;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

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

builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "http://localhost:5287";
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false
        };
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

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();