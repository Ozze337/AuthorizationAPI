using Microsoft.AspNetCore.Identity;

namespace AuthorizationAPI.Database
{
    public class Teacher : User
    {
        public string? Name { get; set; }


    }
}
