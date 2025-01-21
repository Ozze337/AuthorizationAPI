using Microsoft.AspNetCore.Identity;

namespace AuthorizationAPI.Database
{
    public class Admin : IdentityUser
    {
        public string? Name { get; set; }
        public bool IsStudent { get; set; }

        public bool IsTeacher { get; set; }
    }
}
