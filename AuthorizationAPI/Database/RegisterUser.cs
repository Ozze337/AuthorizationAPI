using AuthorizationAPI.Database;
using Microsoft.AspNetCore.Identity;

public class UserRegistrationService
{
    public static async Task RegisterUser(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, string email, string password)
    {
        var user = new User { UserName = email, Email = email };
        var result = await userManager.CreateAsync(user, password);
        if (result.Succeeded)
        {
            string role = "Student";

            if (email.EndsWith("@admin.com"))
            {
                role = "Admin";
            }
            else if (email.EndsWith("@teacher.com"))
            {
                role = "Teacher";
            }

            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
            }
            await userManager.AddToRoleAsync(user, role);
        }
    }
}
