using Microsoft.AspNetCore.Identity;

namespace AuthorizationAPI.Database
{
    public class Teacher : IdentityUser
    {
        public string? Name { get; set; }
        public bool IsAdmin { get; set; }
        public bool IsStudent { get; set; }

    }
}
