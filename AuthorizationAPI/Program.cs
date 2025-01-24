using AuthorizationAPI.Database;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings.
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 2;
    options.Password.RequiredUniqueChars = 1;

    // Lockout settings.
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings.
    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = false;
});


builder.Services.AddAuthentication().AddBearerToken(IdentityConstants.BearerScheme);

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"))
    .AddPolicy("RequireTeacherRole", policy => policy.RequireRole("Teacher"))
    .AddPolicy("RequireStudentRole", policy => policy.RequireRole("Student"));

builder.Services.AddIdentityCore<User>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddApiEndpoints();

builder.Services.AddEndpointsApiExplorer();
//add swagger with jwt
builder.Services.AddSwaggerGen(options =>
{
    //add jwt
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            []
        }
    });
});


var app = builder.Build();


app.MapIdentityApi<User>();
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var dbContext = services.GetRequiredService<AppDbContext>();
    dbContext.Database.Migrate();
}
    using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var dbContext = services.GetRequiredService<AppDbContext>();
    var userManager = services.GetRequiredService<UserManager<User>>();
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    dbContext.Database.Migrate();

    //create admin account if there are no users
    if (!dbContext.Users.Any())
    {

        var admin = new User
        {
            UserName = "admin@wp.pl",
            Email = "admin@wp.pl",
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(admin, "qwerty");

        //throw exception if failed
        if (result.Succeeded == false)
        {
            throw new Exception("Cannot create admin account");
        }

        //check if admin role exists

        if (!await roleManager.RoleExistsAsync("Admin"))
        {
            await roleManager.CreateAsync(new IdentityRole("Admin"));
        }

        await userManager.AddToRoleAsync(admin, "Admin");

        //save changes
        await dbContext.SaveChangesAsync();
    }
}

app.MapGet("students/me", async (ClaimsPrincipal claims, AppDbContext context) =>
{
    var userId = claims.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
    return await context.Students.FindAsync(userId);
})
    .RequireAuthorization("RequireStudentRole");

app.MapGet("teachers/me", async (ClaimsPrincipal claims, AppDbContext context) =>
{
    var userId = claims.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
    return await context.Teachers.FindAsync(userId);
})
    .RequireAuthorization("RequireTeacherRole");

app.MapGet("admins/me", async (ClaimsPrincipal user, AppDbContext context) =>
{
    var userId = user.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
    var name = user.Identity!.Name!;
    //get user from db
    var userFromDb = context.Users.Find(userId);
    return userFromDb;
})
    .RequireAuthorization("RequireAdminRole");

app.MapGet("/me", async (ClaimsPrincipal claims, AppDbContext context) =>
{
    var userId = claims.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
    if(userId == null)
    {
        throw new ArgumentNullException(nameof(userId));
    }
    var user = await context.Users.FindAsync(userId);

    if (await context.Students.AnyAsync(s => s.Id == userId))
    {
        return await context.Students.FindAsync(userId);
    }
    else if (await context.Teachers.AnyAsync(t => t.Id == userId))
    {
        return await context.Teachers.FindAsync(userId);
    }
    else if (await context.Admins.AnyAsync(a => a.Id == userId))
    {
        return await context.Admins.FindAsync(userId);
    }
    else
    {
        return user;
    }
});
app.MapPost("/assign-role", async (string userId, string role, UserManager<User> userManager, RoleManager<IdentityRole> roleManager) =>
{
    var user = await userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return Results.NotFound("User not found");
    }

    if (!await roleManager.RoleExistsAsync(role))
    {
        return Results.BadRequest("Role does not exist");
    }

    var result = await userManager.AddToRoleAsync(user, role);
    if (result.Succeeded)
    {
        return Results.Ok("Role assigned successfully");
    }

    return Results.BadRequest("Failed to assign role");
})
.RequireAuthorization("RequireAdminRole");
app.MapPost("/remove-role", async (string userId, string role, UserManager<User> userManager, RoleManager<IdentityRole> roleManager) =>
{
    var user = await userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return Results.NotFound("User not found");
    }

    if (!await roleManager.RoleExistsAsync(role))
    {
        return Results.BadRequest("Role does not exist");
    }

    var result = await userManager.RemoveFromRoleAsync(user, role);
    if (result.Succeeded)
    {
        return Results.Ok("Role removed successfully");
    }

    return Results.BadRequest("Failed to remove role");
})
.RequireAuthorization("RequireAdminRole");
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("users/me", async (ClaimsPrincipal claims, AppDbContext context) =>
{
    var userId = claims.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
    return await context.Users.FindAsync(userId);
})
    .RequireAuthorization();
app.MapGet("manage/rolesAndClaims", (ClaimsPrincipal user) => {
    return Results.Ok(new
    {
        Roles = user.FindAll(ClaimTypes.Role).Select(claim => claim.Value),
        Claims = user.Claims.ToDictionary(claim => claim.Type, claim => claim.Value)
    });
}).RequireAuthorization();
app.UseHttpsRedirection();


app.Run();