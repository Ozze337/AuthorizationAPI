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

app.MapGet("/me", async (ClaimsPrincipal claims, AppDbContext context) =>
{
    var userId = claims.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (userId == null)
    {
        throw new ArgumentNullException(nameof(userId));
    }
    var user = await context.Users.FindAsync(userId);

    return user;
});
var allowedRoles = new List<string> { "Admin", "Teacher", "Student" };
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

    foreach (var role in allowedRoles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
}

app.MapPost("/assign-role", async (string email, string role, UserManager<User> userManager, RoleManager<IdentityRole> roleManager) =>
{
    if (!allowedRoles.Contains(role))
    {
        return Results.BadRequest("Role is not allowed");
    }

    var user = await userManager.FindByEmailAsync(email);
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

//dd
app.MapPost("/remove-role", async (string email, string role, UserManager<User> userManager, RoleManager<IdentityRole> roleManager) =>
{
    if (!allowedRoles.Contains(role))
    {
        return Results.BadRequest("Role is not allowed");
    }

    var user = await userManager.FindByEmailAsync(email);
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

app.MapPost("/classes", async (ClaimsPrincipal claims, AppDbContext context, string name, string description) =>
{


    if (string.IsNullOrWhiteSpace(description))
    {
        return Results.BadRequest("Description is required.");
    }


    var userId = claims.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId))
    {
        return Results.BadRequest("User ID is not found in the claims.");
    }

    var teacher = await context.Users.FindAsync(userId);
    if (teacher == null)
    {
        return Results.BadRequest("Teacher not found.");
    }

    var newClass = new Class
    {
        Name = name,
        Description = description,
        Teacher = teacher
    };


    context.Classes.Add(newClass);
    await context.SaveChangesAsync();

    return Results.Ok(newClass);
})
.RequireAuthorization("RequireTeacherRole");

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.MapGet("users/me", async (ClaimsPrincipal claims, AppDbContext context, UserManager<User> userManager) =>
{
    var userId = claims.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (userId == null)
    {
        return Results.BadRequest("User ID is not found in the claims.");
    }

    var user = await context.Users.Include(u => u.Class).ThenInclude(c => c.Students).FirstOrDefaultAsync(u => u.Id == userId);

    if (user == null)
    {
        return Results.NotFound("User not found");
    }

    var roles = await userManager.GetRolesAsync(user);

    var response = new
    {
        User = new
        {
            user.Id,
            user.UserName,
            user.Email,
            user.Name
        },
        Class = user.Class != null ? new
        {
            user.Class.Id,
            user.Class.Name,
            user.Class.Description,
            Students = user.Class.Students.Select(s => new { s.Id, s.UserName, s.Email })
        } : null
    };

    return Results.Ok(response);
})
.RequireAuthorization();

app.MapPost("/classes/{className}/add-student", async (ClaimsPrincipal claims, string className, string studentEmail, AppDbContext context, UserManager<User> userManager) =>
{
    // Retrieve the user ID from claims
    var userId = claims.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId))
    {
        return Results.BadRequest("User ID is not found in the claims.");
    }

    // sprawdza czy user ma role teacher lub admin
    var user = await userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return Results.NotFound("User not found");
    }

    var roles = await userManager.GetRolesAsync(user);
    if (!roles.Contains("Teacher") && !roles.Contains("Admin"))
    {
        return Results.Forbid();
    }

    //znajdz klase
    var classEntity = await context.Classes.Include(c => c.Students).FirstOrDefaultAsync(c => c.Name == className);
    if (classEntity == null)
    {
        return Results.NotFound("Class not found");
    }

    // znajdz ucznia
    var student = await userManager.FindByEmailAsync(studentEmail);
    if (student == null)
    {
        return Results.NotFound("Student not found");
    }

    classEntity.Students.Add(student);
    await context.SaveChangesAsync();

    return Results.Ok("Student added to class successfully");
})
.RequireAuthorization(policy => policy.RequireRole("Teacher", "Admin"));

app.MapDelete("/classes/{className}/remove-student", async (ClaimsPrincipal claims, string className, string studentEmail, AppDbContext context, UserManager<User> userManager) =>
{

    var userId = claims.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(userId))
    {
        return Results.BadRequest("User ID is not found in the claims.");
    }


    var user = await userManager.FindByIdAsync(userId);
    if (user == null)
    {
        return Results.NotFound("User not found");
    }

    var roles = await userManager.GetRolesAsync(user);
    if (!roles.Contains("Teacher") && !roles.Contains("Admin"))
    {
        return Results.Forbid();
    }


    var classEntity = await context.Classes.Include(c => c.Students).FirstOrDefaultAsync(c => c.Name == className);
    if (classEntity == null)
    {
        return Results.NotFound("Class not found");
    }


    var student = await userManager.FindByEmailAsync(studentEmail);
    if (student == null)
    {
        return Results.NotFound("Student not found");
    }


    if (!classEntity.Students.Remove(student))
    {
        return Results.BadRequest("Student is not in the class");
    }

    await context.SaveChangesAsync();

    return Results.Ok("Student removed from class successfully");
})
.RequireAuthorization(policy => policy.RequireRole("Teacher", "Admin"));

app.MapGet("manage/rolesAndClaims", (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        Roles = user.FindAll(ClaimTypes.Role).Select(claim => claim.Value),
        Claims = user.Claims.ToDictionary(claim => claim.Type, claim => claim.Value)
    });
}).RequireAuthorization();

app.MapGet("/get-class", async (AppDbContext context) =>
{
    var classes = await context.Classes
        .Include(c => c.Teacher)
        .Include(c => c.Students)
        .ToListAsync();

    return Results.Ok(classes.Select(c => new
    {
        c.Id,
        c.Name,
        c.Description,
        Teacher = new { c.Teacher.Id, c.Teacher.UserName, c.Teacher.Email },
        Students = c.Students.Select(s => new { s.Id, s.UserName, s.Email })
    }));
})
.RequireAuthorization(policy => policy.RequireRole("Teacher", "Admin"));

app.MapDelete("/delete-class/{className}", async (int classId, AppDbContext context) =>
{
    var classEntity = await context.Classes.FindAsync(classId);
    if (classEntity == null)
    {
        return Results.NotFound("Class not found");
    }

    context.Classes.Remove(classEntity);
    await context.SaveChangesAsync();

    return Results.Ok("Class deleted successfully");
})
.RequireAuthorization(policy => policy.RequireRole("Teacher", "Admin"));


app.UseHttpsRedirection();


app.Run();