using SignupAndLoginAPI.Services;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddSingleton<FirestoreService>();
builder.Services.AddOpenApi();

builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi(); 
}

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "SignupAndLoginAPI v1");
    c.RoutePrefix = string.Empty; // Makes Swagger available at root: /
});

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
