using Microsoft.AspNetCore.Identity;

namespace AuthorizationAPI.Database
{
    public class User : IdentityUser
    {
        public string? Name { get; set; }
    }
}
