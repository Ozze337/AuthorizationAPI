using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace AuthorizationAPI.Database
{
    public class Student : IdentityUser
    {
        public string? Name { get; set; }
        public bool IsAdmin { get; set; }
        public bool IsTeacher { get; set; }

    }
}
